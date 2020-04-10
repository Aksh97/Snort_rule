# -*- coding: utf-8 -*-
"""
Created on Thu Apr 07 9:13:33 2020

@author: Akshay Sachdeva
"""
import sys, binascii, os, random
from os.path import isfile, join

global x
import uuid

class AutoSnort:
    def __init__(self,source="any", destination="any",sourcePort="any",destinationPort="any",protocol="tcp",file="arp_spoof.pcap"):
        id = str(int(uuid.uuid1()))
        #Begin global variables
        self.file = file
        self.fileString = ""
        self.source = source
        self.destination = destination
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.protocol = protocol
        self.matchSignature = ""
        self.signature = ""
        self.size = 8
        self.fileExtension = ""
        self.verbose = True
        self.directory = ""
        self.rand = False
        self.sid= id[:10]
        self.flow= " established, to_server; "
        self.process = "GET"
        self.method =" http_method;"
        self.httpform = " http_uri;"
        self.classtype = " trojan-activity;"
        self.rev = " 1;"
        
        
    #Function to print certain lines only if self.verbose is True
    def vPrint(self,x):
        self.verbose
        if self.verbose == True:
            print(x)
        
    #Function to parse a self.directory calling all filse within the self.directory
    def dirParse(self):
        
        self.directory
        print("Processing self.directory: " + self.directory)
        #Create a list of self.files to be parsed
        self.files = [f for f in os.listdir(self.directory) if isfile(join(self.directory,f)) ]
        self.vPrint(self.files)
        for x in self.files:
            #Parsing each self.file requires path + self.file name
            self.fileParse(self.directory + x)
        

    #argRead() takes in the args and prints help if needed
    def argRead(self):
        self.file
        self.source
        self.destination
        self.protocol
        self.size
        self.fileExtension
        self.verbose
        self.directory
        self.rand
        
      #  parser = argparse.ArgumentParser(description="AutoSnortself.signature")
      #  parser.add_argument("-f","--self.file",help="Input self.file name",required=False)
      #  parser.add_argument("-s","--self.source",help="self.source IP (port optional).Format example 192.168.100.1 or 192.168.100.1:22",required=False)
#        parser.add_argument("-d","--self.destination",help="self.destination IP (port optional). Format   example 192.168.100.1 or 192.168.100.1:22",required=False)
#        parser.add_argument("-p","--self.protocol",help="Specify the self.protocol. Acceptable input IP, TCP, UDP, ICMP",required=False)
#        parser.add_argument("-l","--length",help="Specify the self.signature length in number of bytes (1 -64)",required=False)
#        parser.add_argument("-v","--self.verbose",help="Enable self.verbose output mode",required=False,action='store_true')
#        parser.add_argument("-a","--all",help="Parse all self.files within the given self.directory",required=False)
#        parser.add_argument("-r","--random",help="randomize starting point to provide additional security",required=False,action='store_true')
#        args = parser.parse_args()
#        if args.self.file is not None:
#            self.file = args.self.file
#            temp, self.fileExtension = os.path.splitext(self.file)
#        if args.self.source is not None:
#            self.source = args.self.source
#        if args.self.destination is not None:
#            self.destination = args.self.destination
#        if args.self.protocol is not None:
#            self.protocol = args.self.protocol
#        if args.length is not None:
#            self.size = int(args.length)
#        if args.self.verbose is not False:
#            self.verbose = True
#        if args.all is not None:
#            self.directory = args.all
#            self.directory = self.directory.replace("\\","/")
#            if self.directory[-1] != '/':
#                self.directory = self.directory + '/'
#        if args.random is not False:
#            self.rand = True

    #Reads in the provided self.file and stores it as a String of hex characters
    def fileRead(self):
        self.fileString
        self.file
        
        with open(self.file, "rb") as f:
            self.content = f.read()
        self.fileString = binascii.hexlify(self.content)
        #print("1")
        #print(self.fileString[:6])
        
        #Limit maximum portion of self.file to be processed to 10mb
        if (len(self.fileString) > 2621440):
            self.fileString = self.fileString[:2621440]
            #print(self.fileString[:6])



    #Validates self.source and self.destination if set otherwise defaluts to any
    def ipCheck(self):
        #Code here to validate the ports
        if self.sourcePort != "any":
            self.vPrint("Validating self.source port")
            self.validPort(self.sourcePort)
        if self.destinationPort != "any":
            self.vPrint("Validating self.destination port")
            self.validPort(self.destinationPort)
        #Code here to validate the IP addresses
        if self.source != "any":
            self.vPrint("Checking self.source IP")
            self.validIP(self.source)
        if self.destination != "any":
            self.vPrint("Checking self.destination IP")
            self.validIP(self.destination)
        #Print values to be used. Can later be disabled
        print("self.source IP is " + self.source)
        print("self.source port is " + self.sourcePort)
        print("self.destination IP is " + self.destination)
        print("self.destination port is " + self.destinationPort)
   
    #Check whether a port is numeric and within the correct range (0-65535)
    def validPort(self,port):
        
        if port.isdigit() == True:
            num = int(port)
            #test = (-1 < num)
            #print(test)
            if -1 < num and num < 65536:
                return True
            else:
                print("Invalid port found. Exiting")
                sys.exit(2)
        else:
            print("Invalid port found. Exiting")
            sys.exit(2)
        
        
        #Check whether a valid IP address is provided
    def validIP(self,ip):
        if ip.count(".") != 3:
            print("Invalid IP address found. Exiting")
            sys.exit(2)
        self.vPrint("Checking octave 1")
        where = ip.find(".") #Check first octave
        if (where > -1):
            if (self.validOctave(ip[:where]) == False):
                print("Invalid IP found")
                sys.exit(2)
            else:
                ip = ip[where+1:]
        else:
            print("Invalid IP found")
            sys.exit(2)
        self.vPrint("Checking octave 2")
        where = ip.find(".") #Check second octave
        if (where > -1):
            if (self.validOctave(ip[:where]) == False):
                print("Invalid IP found")
                sys.exit(2)
            else:
                ip = ip[where+1:]
        else:
            print("Invalid IP found")
            sys.exit(2)
        self.vPrint("Checking octave 3")
        where = ip.find(".") #Check third octave
        if (where > -1):
            if (self.validOctave(ip[:where]) == False):
                print("Invalid IP found")
                sys.exit(2)
            else:
                ip = ip[where+1:]
        else:
            print("Invalid IP found")
            sys.exit(2)
        self.vPrint("Checking octave 4")
       	if (self.validOctave(ip) == False):
            #Check fourth octave
            print("Invalid IP found")
            sys.exit(2)   
    

    #Check if provided input is a valid octave
    def validOctave(self,octave):
        if octave.isdigit() == True:
            if (-1 < int(octave) < 256):
                #print("Returning true on octave check")
                return True
            else:
                print("Invalid octave found. Exiting")
                sys.exit(2)
        else:
            print("Invalid octave found. Exiting")
            sys.exit(2)
        #Check if the size is between 1 and 64. If not set the size to the default 8.

    def validSize(self):
        self.size
        print("Size is: " + str(self.size))
        if 3 < self.size and self.size < 65:
            print("Valid signature size found")
            return True
        else:
            print("Invalid size found setting size to the default")
            self.size = 8


    #Check if a valid Snort self.protocol was specifed. If not alter self.protocol to any
    def validprotocol(self):
        self.protocol
        acceptable = ["ip","tcp","udp","icmp","any"]
        self.protocol = self.protocol.lower()
        if self.protocol not in acceptable:
            self.protocol = "any"
            print("Invalid self.protocol value detected. Setting to the default any")

    #Reads the self.file self.contents and stores the hex string that needs matching
    #Starts at the middle of the self.file and pulls hex strings until one is found with an acceptable amount of empty (0) values
    def createSig(self):
        self.matchSignature
        self.signature
        self.fileString
        self.size
        self.rand
        #print("i a , herergty")
        #copy hex string for local manipulation
        #print(self.fileString[:6])
        temp = self.fileString
        
        
        #variable to store the hex pairs that represent a byte
        self.fileHexArray=[]
        #populating the array
        while temp.__len__() > 0:
            
            self.fileHexArray.append(temp[:2])
            temp = temp[2:]
        length = len(self.fileHexArray)
        start = int((length/2) - (self.size/2))
        #Check if self.random is true
        #print("great")
        #print(self.matchSignature[:6])
        #If true alter the starting point by placing it in a self.random location from 25% to 75% of self.file length
        if self.rand == True:
            random.seed
            #Create variable for 0 to 25% self.file length
            alter = random.randint(0,start//2)
            #Either add or subtract the variable from start
            add = random.randint(0,1)
            if add == 0:
                start = start + alter
            else:
                start = start - alter
                self.matchSignature = ""
            #extracting the self.signature
            print("size")
            print(self.size)
            print("start=")
        for i in range(self.size):
            temp = self.fileHexArray[start + i]
            
            temp = str(temp)
            temp = temp[2:4] #stripping the b' and ' characters leaving only the two hex characters
            #print(temp[:6]+"temp")
            self.matchSignature = self.matchSignature + temp
            #Determine the occurence of 0 in the self.signature. If greater then 50% loop through the hex string searching
            #for a self.signature that has few enough 0 to be unique. Designed to pself.revent self.signatures that are padding.
        count = self.matchSignature.count("0")
        while (count > (self.size//2)):
            start = start + self.size
            if (start + self.size) > length:
                print("Unable to find a suitable string. Try decreasing the string size")
                sys.exit(2)
            self.matchSignature = ""
            for i in range(self.size):
                temp = self.fileHexArray[start + i]
                temp = str(temp)
                temp = temp[2:4]
                self.matchSignature = self.matchSignature + temp
            count = self.matchSignature.count("0") 
            #print("check3")
            #print(self.matchSignature[:6])

    #Combines all the self.signature elements into a valid signature string
    def combineSig(self):

        self.signature = "SNORT Rule: " + " " +" alert "
        self.signature = self.signature + self.protocol + " "
        self.signature = self.signature + self.source + " "
        self.signature = self.signature + self.sourcePort + " -> "
        self.signature = self.signature + self.destination + " "
        self.signature = self.signature + self.destinationPort + " "
        
        self.signature = self.signature + "(msg:\"" + self.file + "\";"
        self.signature = self.signature + "flow:" + self.flow
        self.signature = self.signature + "content:\"" + self.process + "\";"
        self.signature = self.signature + self.method
        self.signature = self.signature + "content:\"|" + self.matchSignature + "|\";"
        
        self.signature = self.signature + self.httpform
        self.signature = self.signature + "classtype:" + self.classtype
        self.signature = self.signature + "sid: " + self.sid + ";"
        self.signature = self.signature + "rev:" + self.rev + ")"
        print(self.signature)
        
        

    def execute(self):
        
#        global self.file
#        global self.directory
        self.argRead()
        #Determine if a self.file or a self.directory needs to be parsed
        if self.file == "" and self.directory == "":
            print("Either a self.directory or a self.file must be specified.")
        elif self.file != "" and self.directory != "":
            print("self.file and self.directory are exclusive options. Only one may be enabled at a time.")
        elif self.file != "":
            self.fileParse(self.file)
        else:
            self.dirParse()

        return self.signature

    #Function to process a single self.file
    def fileParse(self,toDo):
        
        self.fileString
        self.fileExtension
        self.file
        self.file = toDo
        self.vPrint("File to be read " + self.file)
        self.vPrint("File extension: " + self.fileExtension)
        self.fileRead()
        #test if self.file is being read in properly
        #print(self.fileString)
        self.ipCheck()
        self.validSize()
        self.validprotocol()
        self.createSig()
        self.combineSig()
        
       
