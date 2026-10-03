'''
    practica1.py
    Autor: Javier Ramos <javier.ramos@uam.es>
    Modificado para cumplir los requisitos de la Práctica 1.
'''

from rc1_pcap import *
import sys
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60

first_ts = None
last_ts = None
dumper_ip = None
dumper_noip = None
handle = None

def signal_handler(nsignal, frame):
    logging.info('Control C pulsado')
    if handle:
        pcap_breakloop(handle)

def procesa_paquete(us, header, data):
    global num_paquete, first_ts, last_ts, dumper_ip, dumper_noip, args
    
    current_ts = header.ts.tv_sec + (header.ts.tv_usec / 1_000_000.0)
    
    if first_ts is None:
        first_ts = current_ts
    last_ts = current_ts
    
    num_paquete += 1
    logging.info('Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{}'.format(header.len, header.ts.tv_sec, header.ts.tv_usec))

    # Escribir el tráfico a los ficheros si la captura es en vivo (--itf)
    if args.interface:
        # Si el byte 12 es 0x08 y el 13 es 0x06, va a la traza NOIP
        if len(data) >= 14 and data[12] == 0x08 and data[13] == 0x06:
            pcap_dump(dumper_noip, header, data)
        else:
            pcap_dump(dumper_ip, header, data)

    bytes_to_print = len(data)
    if args.nbytes is not None:
        bytes_to_print = min(args.nbytes, len(data))
        
    byte_list = [f"{b:02X}" for b in data[:bytes_to_print]]
    
    print(f"--- Paquete {num_paquete} ---")
    for i in range(0, len(byte_list), 16):
        print(" ".join(byte_list[i:i+16]))
    print("")

if __name__ == "__main__":
    global args
    parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los paquetes',
    formatter_class=RawTextHelpFormatter)
    parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
    parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
    # Modificamos el valor por defecto de nbytes a None para detectar si el usuario lo introduce o no
    parser.add_argument('--nbytes', dest='nbytes', type=int, default=None,help='Número de bytes a mostrar por paquete (por defecto: todos)')
    # Añadimos el nuevo argumento npkts
    parser.add_argument('--npkts', dest='npkts', type=int, default=-1,help='Número de paquetes a procesar (por defecto: indefinido)')
    parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
    else:
        logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

    if args.tracefile is False and args.interface is False:
        logging.error('No se ha especificado interfaz ni fichero')
        parser.print_help()
        sys.exit(-1)

    signal.signal(signal.SIGINT, signal_handler)

    errbuf = bytearray()
    
    if args.tracefile:
        handle = pcap_open_offline(args.tracefile, errbuf)
    elif args.interface:
        handle = pcap_open_live(args.interface, ETH_FRAME_MAX, PROMISC, TO_MS, errbuf)
        
        ts_sec = int(time.time())
        fname_noip = f"capturaNOIP.{args.interface}.{ts_sec}.pcap"
        fname_ip = f"captura.{args.interface}.{ts_sec}.pcap"
        
        descr_dead = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)
        dumper_noip = pcap_dump_open(descr_dead, fname_noip)
        dumper_ip = pcap_dump_open(descr_dead, fname_ip)

    if handle is None:
        logging.error(f"Error al abrir la fuente: {errbuf.decode('utf-8', 'ignore')}")
        sys.exit(-1)

    ret = pcap_loop(handle, args.npkts, procesa_paquete, None)
    
    if ret == -1:
        logging.error('Error al capturar un paquete')
    elif ret == -2:
        logging.debug('pcap_breakloop() llamado')
    elif ret == 0:
        logging.debug('No mas paquetes o limite superado')
        
    logging.info('{} paquetes procesados'.format(num_paquete))

    if num_paquete >= 2 and first_ts is not None and last_ts is not None:
        diff = last_ts - first_ts
        print(f"Diferencia de tiempo entre el último y primer paquete: {diff:.6f} segundos")
    else:
        print("Diferencia de tiempo entre el último y primer paquete: 0 segundos")

    if dumper_ip: 
        pcap_dump_close(dumper_ip)
    if dumper_noip: 
        pcap_dump_close(dumper_noip)
    if handle: 
        pcap_close(handle)