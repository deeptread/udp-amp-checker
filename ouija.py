import os, sys, time, socket
from scapy.all import *
from colorama import Fore

_abort = False

def main():
    global _abort
    os.system('clear')
    
    if len(sys.argv) != 6:
        # Reflector list format = <ip>:<port>
        sys.exit('\r\n\033[1m\033[37m   USAGE: <REFLECTORS.TXT> <OUTPUT.TXT> <TIMEOUT SEC> <WAIT SEC> <METHOD:SYN/UDP>')
    
    if not os.geteuid() == 0:
        sys.exit('\r\n\033[1m\033[31m   SCRIPT REQUIRES ROOT ELEVATION!')

    if not (sys.argv[5].lower() == "udp" or sys.argv[5].lower() == "syn"):
        sys.exit('\r\n\033[1m\033[31m ERROR! INVALID METHOD. EXITING...')

    print('''\033[1m\033[37m
       * ***                                            
     *  ****                    *       *               
    *  *  ***                  ***     ***              
   *  **   ***                  *       *               
  *  ***    *** **   ****                               
 **   **     **  **    ***  * ***     ***       ****    
 **   **     **  **     ****   ***     ***     * ***  * 
 **   **     **  **      **     **      **    *   ****  
 **   **     **  **      **     **      *    **    **   
 **   **     **  **      **     **     *     **    **   
  **  **     **  **      **     **    ***    **    **   
   ** *      *   **      **     **     ***   **    **   
    ***     *     ******* **    **      ***  **    **   
     *******       *****   **   *** *    ***  ***** **  
       ***                       ***      **   ***   ** 
                                          **            
                                          *             
                                         *              
                                        *      
 ''')
 
    _online = []
    i = 0
    
    try:
        with open(sys.argv[1], 'r') as f:
            for line in f:
                if _abort == True:
                    sys.exit("\033[1m\033[31m ABORTED BY USER...")
                    break
                # retrieve IP:PORT
                try:
                    _ip, _prt = line.strip().split(':')
                except:
                    print('\033[1m\033[37m[{}]'.format(str(i)) + '\033[1m\033[34mANOMALY DETECTED @ LINE ENTRY "' + line + '"')

                i +=1
                if sys.argv[5].lower() == "syn":
                #  ___ _   _ _ __  
                # / __| | | | '_ \ 
                # \__ \ |_| | | | |
                # |___/\__, |_| |_|
                #      |___/         
                    try:
                        response = sr1(IP(dst=_ip)/TCP(dport=int(_prt), flags="S"), timeout=int(sys.argv[3]), verbose=0)
                        if response and response.haslayer(TCP):
                            if response[TCP].flags == 0x12:
                                # open
                                print('\033[1m\033[37m[{}]'.format(str(i)) + '\033[1m\033[32m ------> OPEN @ ' + _ip + ':' + _prt)
                                success = _ip + ":" + _prt
                                _online.append(success)
                            else:
                                # closed/filtered
                                print('\033[1m\033[37m[{}]'.format(str(i)) + '\033[1m\033[31m TIMEOUT @ ENDPOINT ' + _ip + ':' + _prt)
                        else:
                            print('\033[1m\033[37m[{}]'.format(str(i)) + '\033[22m\033[31m SYN/ACK NOT RECEIVED. REJECTED BY ENDPOINT ' + _ip + ':' + _prt)
                    except KeyboardInterrupt:
                        sys.exit()
                    except:
                        pass
                    
                else:
                #            _       
                #  _   _  __| |_ __  
                # | | | |/ _` | '_ \ 
                # | |_| | (_| | |_) |
                #  \__,_|\__,_| .__/ 
                #             |_|  
                    try:
                        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        udp_socket.settimeout(1)  # Set a timeout for the connection attempt
                        udp_socket.sendto(b'', (_ip, int(_prt)))
                        data, addr = udp_socket.recvfrom(1024)  # Receive response
                        # open
                        print('\033[1m\033[37m[{}]'.format(str(i)) + '\033[1m\033[32m ------> OPEN @ ' + _ip + ':' + _prt)
                    except KeyboardInterrupt:
                        sys.exit()
                    except:
                        print('\033[1m\033[37m[{}]'.format(str(i)) + '\033[22m\033[31m SYN/ACK NOT RECEIVED. REJECTED BY ENDPOINT ' + _ip + ':' + _prt)
            
    except KeyboardInterrupt:
        # user abort via ctrl+c
        _abort = True 
    except ValueError:
        # malformed string formate
        print('\033[1m\033[37m[{}]'.format(str(i)) + '\033[1m\033[34mANOMALY DETECTED @ LINE ENTRY "' + line + '"')
    except:
        # who knows lol
        print('\033[1m\033[31mCRITICAL ERROR ENCOUNTERED!')
    
    # save all open ports to output file
    print('\r\n\033[1m\033[37mDUMPING OPEN PORTS TO OUTPUT FILE. PLEASE STAND-BY...')
    try:
        with open(sys.argv[2], 'w') as file:
            for item in _online:
                file.write(item + '\n')
    except KeyboardInterrupt:
        sys.exit()
    except:
        print('\033[1m\033[31mERROR ENCOUNTERED WHEN WRITING TO FILE!')
    
    # remove root file-attribute from output file
    try:
        current_mode = os.stat(sys.argv[2]).st_mode
        new_mode = current_mode & ~0o4000
        os.chmod(file_path, new_mode)
    except:
        pass

    sys.exit('\r\n\033[1m\033[37mJOB FINISHED.')
         
if __name__ == "__main__":
    main()
 
 
 
 
 
 
 
 
 
