'''
    ethmsg.py
    Implementación del protocolo de mensajeria basica para emision de mensajes en tiempo real sobre ethernet.
    Autor: Manuel Ruiz <manuel.ruiz.fernandez@uam.es>
    2024 EPS-UAM
'''

from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

ETHTYPE = 0x0AA0
#Dirección de difusión (Broadcast)
broadcast = bytes([0xFF]*6)




def process_ethMsg_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    '''
        Nombre: process_EthMsg_frame
        Descripción: Esta función procesa las tramas mensajes sobre ethernet. 
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype ETHTYPE (si ha sido registrada en initEth). 
                - Imprimir el contenido de los datos indicando la direccion MAC del remitente así como el tiempo de recepcion del mensaje, según el siguiente formato:
					[<segundos.microsegundos>] <MAC>: <mensaje> 
                - En caso de que no exista retornar
            
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ethMsg. Los dos primeros bytes tienen la longitud del mensaje en orden de red. El resto de bytes son el mensaje en sí mismo.
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    if len(data) < 2:
        return
        
    msg_len = struct.unpack('!H', data[0:2])[0]
    
    msg_bytes = data[2:2 + msg_len]
    mensaje = msg_bytes.decode('utf-8', errors='ignore')
    
    mac_str = ':'.join(['{:02X}'.format(b) for b in srcMac])
    
    fecha_base = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(header.ts.tv_sec))
    timestamp_str = f"{fecha_base}.{header.ts.tv_usec:06d}"

    print(f"[{timestamp_str}] {mac_str} ({msg_len} bytes) : {mensaje}")



def initEthMsg(interface:str) -> int:
    '''
        Nombre: initEthMsg
        Descripción: Esta función construirá inicializará el nivel ethMsg. Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar la función del callback process_ethMsg_frame con el Ethertype ETHTYPE
        Argumentos:   
			interfaz
    '''
    registerEthCallback(process_ethMsg_frame, ETHTYPE)
    return 0

def sendEthMsg(message:bytes) -> bytes:
    '''
        Nombre: sendEthMsg
        Descripción: Esta función mandara un mensaje en broacast 
            
            Esta función debe realizar, al menos, las siguientes tareas:
                - Crear una trama Ehernet con el mensaje remitido. Los datos de la trama tienen que incluir la longitud del mensaje en orden de red, seguido del mensaje.
                - Enviar un mensaje en broadcast. La llamada a Ethernet debe tener en cuenta la longitud total (longitud+mensaje)
		Argumentos:
			message: datos con el mensaje a remitir.
                
        Retorno: 
			Numero de Bytes transmitidos en el mensaje.
			None en caso de que no haya podido emitir el mensaje
                
          
    '''
    if isinstance(message, str):
        msg_bytes = message.encode('utf-8')
    elif isinstance(message, bytes):
        msg_bytes = message
    else:
        msg_bytes = str(message).encode('utf-8')

    msg_len = len(msg_bytes)

    payload = struct.pack('!H', msg_len) + msg_bytes
    total_len = len(payload)

    ret = sendEthernetFrame(payload, total_len, ETHTYPE, broadcast)
    if ret == 0:
        return msg_len
    else:
        logging.error('sendEthMsg: Error al enviar la trama Ethernet')
        return None