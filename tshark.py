__author__ = 'targaryen'

from subprocess import check_output
import xmltodict
from pymongo import MongoClient
import gridfs
import os
import json

class Tshark:

    # SERVER = 'castleblack'
    SERVER = 'castleblack'
    PORT = 27017
    PCAP_DIR = '/opt/pcaps/'
    XML_DIR = '/opt/xmls/'
    JSON_DIR = '/opt/jsons/'

    def __init__(self):
        client = MongoClient(self.SERVER,self.PORT)
        db = client.pcap
        self.fs = gridfs.GridFS(db)

    def save_multiple_files(self, files):
        for file in files:
            self.__save_pcap__(file) #"/home/targaryen/dump_sorted.pcap")

    def __save_pcap__(self, pcap_path):
        filename = os.path.basename(pcap_path)
        json_filename = filename[0:-5]+".json"

        if self.fs.exists(filename=filename) is False or self.pcap_check(filename,pcap_path) is False:
            print "saving "+filename
            with open(pcap_path,"r") as f:
                a = self.fs.put(f, filename=filename) # salva arquivo com nome especifico. "a" eh o _id do registro

        # json_result = self.dissect(pcap_path,True)

        # if self.fs.exists(filename=json_filename) is False or self.json_check(json_filename, json_result) is False:
            # print "saving "+filename
        #     a = self.fs.put(json_result, filename=json_filename) # salva arquivo com nome especifico. "a" eh o _id do registro
        #     test_read(name) # TODO REMOVE

    def dissect(self, pcap_path, remove_first_layers):
        """
        Parser PCAP to xml 
        """
        print "dissecting file "+pcap_path
        pcacp_xml = check_output(["tshark","-T","pdml","-r",pcap_path])
        pcap_dict = xmltodict.parse(pcacp_xml)
        array = pcap_dict ['pdml']['packet']

        if remove_first_layers is True:
            for i in array:
                del i['proto'][0]
                del i['proto'][0]
                del i['proto'][0]

        print "dissect finished for file "+pcap_path
        return json.dumps(array, indent=1)

    def json_check(self, name, json_result):
        for match in self.fs.find({"filename": name}, no_cursor_timeout=True): # busca pelo nome do arquivo, podendo achar varios com mesmo nome
            data = match.read() #retorna um objeto file-like, entao o read() retorna esse arquivo como string
            if (len(data) == len(json_result)):
                print "Already in db. Skipping..."
                return True
            else:
                print "Size of json string in db: "+ str(len(data)) + ". Size of new json string:"+ str(len(json_result))+". Replacing..."
                self.fs.delete(match._id)
                return False

    def pcap_check(self,name, pcap_path):
        for match in self.fs.find({"filename": name}, no_cursor_timeout=True): # busca pelo nome do arquivo, podendo achar varios com mesmo nome
            pcap_size = os.path.getsize(pcap_path)
            
            if (match.length == pcap_size):
                print "Already in db. Skipping..."
                return True
            else:
                print "Size of pcap file in db: "+ str(match.length) + ". Size of new file:"+ str(pcap_size)+". Replacing..."
                self.fs.delete(match._id)
                return False