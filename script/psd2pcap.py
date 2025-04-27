# !/usr/bin/env python3

# psd2pcap.py
#
# Requirements: Python 3.8+, Wireshark (text2pcap.exe in PATH)
# Usage: python psd2pcap.py input.psd
#
# Copyright (c) 2025 shoderico
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Description: Converts Packet Sniffer PSD files to PCAP format for Wireshark analysis.
# Author: shoderico
# License: MIT License (see LICENSE file in the repository for details)
# Repository: https://github.com/shoderico/tilta-zigbee-analysis

# Special Thanks to :
#  * @tansokun920 ( https://qiita.com/tansokun920 )
#    https://qiita.com/tansokun920/items/af126b298a46acc3317a


import sys
import os
from enum import Enum, IntEnum
from datetime import timedelta

class ReadStatus(Enum):
    PacketInfo = 0
    PacketNumber = 1
    Timestamp = 2
    Length = 3
    Payload = 4
    Spare = 5

class Length(IntEnum):
    PacketInfo   = 1
    PacketNumber = 4
    Timestamp    = 8
    Length       = 2

    Packet_length_raw_data = 150


def main():

    if(len(sys.argv)>1):
        filename = sys.argv[1]
    else:
        filename = raw_input('file name:')

    print( "Filenane: {}".format(filename) )
    fp = open(filename,"rb")

    read_bytes = 0
    read_status = ReadStatus.PacketInfo
    
    buffer = ""
    data = []
    data_all = []
    
    payload_length = 0
    
    # Packet Length with Spares. ZigBee specific value.
    psd_packet_length = Length.Packet_length_raw_data + 1
    
    psd_payload_length = psd_packet_length
    psd_payload_length = psd_payload_length - Length.PacketInfo
    psd_payload_length = psd_payload_length - Length.PacketNumber
    psd_payload_length = psd_payload_length - Length.Timestamp
    psd_payload_length = psd_payload_length - Length.Length
    
    
    while True:
    
        b = fp.read(1)
        if len(b) == 0:
            break
            
        b_str = '%02x' % b[0]
        b_int = int('0x' + b_str, 16)
        
        read_bytes = read_bytes + 1
        buffer = b_str + buffer
        
        if ( (read_status == ReadStatus.PacketInfo) & (buffer == "03") ):

            # 0x03 : 0000 0011
            #                ^ : Length includes FCS.
            #               ^  : Correlation used.
            #              ^   : Incomplete packet.
            #             ^    : Buffer overflow.
            #           ^      : Generic protocol.

            print( "Packet Information found." )
            read_status = ReadStatus.PacketNumber
            buffer = ""
            
            
        elif ( (read_status == ReadStatus.PacketInfo) ):

            print( "Unknown Packet Information: {}".format( buffer ))
            break
            
            
        elif ( (read_status == ReadStatus.PacketNumber) ):
            
            if ( len( buffer ) == Length.PacketNumber*2 ):
                print( "Packet Number: {}".format( buffer ) )

                read_status = ReadStatus.Timestamp
                buffer = ""
                
                
        elif ( (read_status == ReadStatus.Timestamp) ):

            if ( len( buffer ) == Length.Timestamp*2 ):
                print( "Timestamp: {}".format( buffer ) )
                
                
                # raw data of timestamp is 64 bit counter value.
                timestamp_bytes = bytes.fromhex( buffer )
                timestamp_raw = int.from_bytes( timestamp_bytes )

                # according to the manual,
                #   To calculate the time in microseconds this value must be divided by a number 
                #   depending on the clock speed used to drive the counter tics on the target. 
                #   (E.g. CC243xEM, CC253x -> 32, CCxx10EM -> 26, SmartRF05EB + CC2520EM -> 24).
                timestamp_us = timestamp_raw // 32
                
                # calculate seconds and microseconds
                timestamp_seconds      = timestamp_us // 1_000_000  # 1 sec = 1,000,000 microseconds
                timestamp_microseconds = timestamp_us %  1_000_000

                # seconds to timedelta
                timestamp_obj = timedelta(seconds=timestamp_seconds, microseconds=timestamp_microseconds)
                
                # format to '%H:%M:%S.%f'
                timestamp_str = str( timestamp_obj )
                
                # cut over 24 hour
                if ',' in timestamp_str:
                    timestamp_str = timestamp_str.split(', ')[-1]
                
                
                data.append( timestamp_str )
                
                read_status = ReadStatus.Length
                buffer = ""
                
                
        elif ( (read_status == ReadStatus.Length) ):
        
            if ( len( buffer ) == Length.Length*2 ):
                payload_length = int('0x' + buffer, 16)
                print( "Payload Length: {} {}".format(buffer, payload_length) )
                
                read_status = ReadStatus.Payload
                buffer = ""
        
        
        elif ( (read_status == ReadStatus.Payload) ):
        
            # Skip first byte
            if ( len( buffer ) > 2 ):
                data.append( b_str )

            if ( len( buffer ) == payload_length*2 ):
                print( "Payload: {}".format( buffer ) )
            
                read_status = ReadStatus.Spare
                buffer = ""


        elif ( (read_status == ReadStatus.Spare) ):
            
            if ( len( buffer ) == ( psd_payload_length*2 - payload_length*2 ) ):
                print( "Spare :{}".format( buffer ) )
                read_status = ReadStatus.PacketInfo
                buffer = ""
                
                data_all.append( data )
                data = []


    fp.close
    
    print( "Read Bytes: {}".format(read_bytes) )
    print( "Data Length: {}".format( len(data_all) ) )
    
    export_txt( filename.split(".")[0] + ".txt", data_all )
    os.system( "text2pcap -l 195  -t \"%H:%M:%S.%f\" " + filename.split(".")[0] + ".txt " + filename.split(".")[0] + ".pcap" )
    os.system( "del " + filename.split(".")[0] + ".txt" )


def export_txt( filename, data_all ):
    fp = open(filename, "w")
    for i in range( 0, len(data_all) ):
        timestamp_text = ""
        cnt = 0
        for j in range( 0, len(data_all[i]) ):
        
            if (j == 0):
                fp.write( data_all[i][j] )
                fp.write( " " )
                fp.write( "%03x" % (cnt) + "0" )
                cnt = cnt + 1
            else:
                fp.write(" ")
                fp.write( data_all[i][j] )

        fp.write("\n")
    fp.close


if __name__ == '__main__':
    main()
