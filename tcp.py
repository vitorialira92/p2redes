import asyncio
import random
import time
from grader.tcputils import *

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return

        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum inválido')
            return

        payload = segment[4 * (flags >> 12):]
        conn_id = (src_addr, src_port, dst_addr, dst_port)

        if flags & FLAGS_SYN:
            self._handle_syn_packet(conn_id, src_addr, dst_addr, src_port, dst_port, seq_no)
        elif conn_id in self.conexoes:
            self.conexoes[conn_id]._rdt_rcv(seq_no, ack_no, flags, payload)
            if flags & FLAGS_FIN:
                del self.conexoes[conn_id]
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))

    def _handle_syn_packet(self, conn_id, src_addr, dst_addr, src_port, dst_port, seq_no):
        initial_seq = random.randint(0, 0xffff)
        initial_ack = seq_no + 1
        connection = self.conexoes[conn_id] = Conexao(self, conn_id, initial_seq, initial_ack)

        syn_ack_header = fix_checksum(
            make_header(dst_port, src_port, initial_seq, initial_ack, FLAGS_SYN | FLAGS_ACK),
            src_addr,
            dst_addr
        )
        self.rede.enviar(syn_ack_header, src_addr)

        if self.callback:
            self.callback(connection)


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_no = seq_no + 1
        self.ack_no = ack_no
        self.callback = None
        self.next_seq_num = self.seq_no
        self.unacked_segments = []
        self.timer = None
        self.rtt_stats = RTTManager()
        self.window_size = MSS
        self.data_queue = []
        self.acked_bytes = 0

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if seq_no != self.ack_no:
            return

        if (flags & FLAGS_ACK) and ack_no > self.next_seq_num:
            self._process_ack(ack_no)

        if (flags & FLAGS_FIN):
            payload = b''
            self.ack_no += 1
        elif not payload:
            return

        self.callback(self, payload)
        self.ack_no += len(payload)
        self._send_ack()

    def _process_ack(self, ack_no):
        current_time = time.time()
        bytes_acked = ack_no - self.next_seq_num

        self.acked_bytes += bytes_acked
        if self.acked_bytes >= self.window_size:
            self.window_size += MSS
            self.acked_bytes = 0

        if self.next_seq_num in self.rtt_stats.timings:
            sample_rtt = current_time - self.rtt_stats.timings[self.next_seq_num]
            del self.rtt_stats.timings[self.next_seq_num]
            self.rtt_stats.update_rtt(sample_rtt)

        self.next_seq_num = ack_no
        self._remove_acked_segments(bytes_acked)
        self._update_timer()
        self._try_send_queued_data()

    def _remove_acked_segments(self, bytes_acked):
        remaining = bytes_acked
        while self.unacked_segments and remaining >= self.unacked_segments[0][2]:
            remaining -= self.unacked_segments[0][2]
            self.unacked_segments.pop(0)

    def _update_timer(self):
        if self.unacked_segments:
            self.start_timer()
        elif self.timer:
            self.timer.cancel()

    def _try_send_queued_data(self):
        if self.data_queue:
            self.enviar(self.data_queue.pop(0))

    def _send_ack(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        ack_segment = fix_checksum(
            make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK),
            dst_addr,
            src_addr
        )
        self.servidor.rede.enviar(ack_segment, src_addr)

    def _stop_timer(self):
        if self.timer:
            self.timer.cancel()
        self.timer = None

    def start_timer(self):
        self._stop_timer()
        loop = asyncio.get_event_loop()
        self.timer = loop.call_later(self.rtt_stats.timeout_interval, self._timeout_handler)

    def _timeout_handler(self):
        if not self.unacked_segments:
            return

        self.window_size = (self.window_size // (2 * MSS)) * MSS
        segment, addr, size = self.unacked_segments[0]
        self.servidor.rede.enviar(segment, addr)

        timing_key = self.seq_no - size
        if timing_key in self.rtt_stats.timings:
            del self.rtt_stats.timings[timing_key]

        self.start_timer()

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, data):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        data_len = len(data)
        current_unacked = sum(seg[2] for seg in self.unacked_segments)

        if data_len <= MSS:
            if self._can_send_now(current_unacked, data_len):
                self._send_chunk(data, src_addr, dst_addr, src_port, dst_port)
            else:
                self.data_queue.append(data)
        else:
            if self._can_send_now(current_unacked, MSS):
                self._send_chunk(data[:MSS], src_addr, dst_addr, src_port, dst_port)
                self.enviar(data[MSS:])
            else:
                self.data_queue.append(data)

    def _can_send_now(self, unacked_bytes, data_size):
        return (unacked_bytes + data_size) <= self.window_size

    def _send_chunk(self, chunk, src_addr, dst_addr, src_port, dst_port):
        header = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK), src_addr, dst_addr)
        segment = fix_checksum(header + chunk, src_addr, dst_addr)

        self.servidor.rede.enviar(segment, dst_addr)
        self.rtt_stats.timings[self.seq_no] = time.time()
        self.start_timer()
        self.unacked_segments.append([segment, src_addr, len(chunk)])
        self.seq_no += len(chunk)

    def fechar(self):
        dst_addr, dst_port, src_addr, src_port = self.id_conexao
        header = make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_FIN)
        segmento = fix_checksum(header, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento, dst_addr)


class RTTManager:
    def __init__(self):
        self.estimated_rtt = 0
        self.dev_rtt = 0
        self.timeout_interval = 1
        self.timings = {}

    def update_rtt(self, sample_rtt):
        if self.estimated_rtt == 0:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            self.estimated_rtt = 0.875 * self.estimated_rtt + 0.125 * sample_rtt
            self.dev_rtt = 0.75 * self.dev_rtt + 0.25 * abs(sample_rtt - self.estimated_rtt)

        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt