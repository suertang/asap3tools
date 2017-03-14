# asap3.py 
# (C) 2017 Patrick Menschel
import socket
import struct
import time
import datetime
import queue
import threading
import logging

A3_INIT = 0x1000000
A3_REQ = 0x1000001

A3_ACK = 0xAAAA
A3_CMPL = 0x0
A3_ERR = 0xFFFF
A3_NONIMPL = 0x5656


ASAP3VERSION = 2.1
ASAP3CLIENTVERSION = "0.1beta"


ASAP3ERRORCODES = {0x0:"ACK: Faultless execution of the last command",
                   0x1232:"ACK: Faultless execution of the last command",
                   0x2342:"ERROR: Restart of Communication necessary",
                   0x2344:"INFO: MC System is in simulation mode",
                   0x5656:"ERROR: Command not available",
                   0xAAAA:"ACK: Command received, execution is pending",
                   0xEEEE:"RETRY: repeat the request",
                   0xFFFF:"ERROR: see description",
                   }

ASAP3COMMANDS = {1:"emergency",
                 2:"init",
                 3:"select_description_file_and_binary_file",
                 4:"copy_binary_file",
                 5:"change_binary_filename",
                 6:"select_look-up_table",
                 7:"put_look-up_table",
                 8:"get_look-up_table",
                 9:"get_look-up_table_value",
                 10:"increase_look-up_table",
                 11:"set_look-up_table",
                 12:"parameter_for_value_acquisition",
                 13:"switching_online_offline",
                 14:"get_parameter",
                 15:"set_parameter",
                 16:"set_graphic_mode",
                 17:"reset_device",
                 18:"set_format",
                 19:"get_online_value",
                 20:"identify",
                 21:"get_user_defined_value",
                 22:"get_user_defined_value_list",
                 30:"define_description_and_binary_file",
                 41:"define_recorder_parameters",
                 42:"define_trigger_condition",
                 43:"activate_recorder",
                 44:"get_recorder_status",
                 45:"get_recorder_result_header",
                 46:"get_recorder_results",
                 47:"save_recorder_file",
                 48:"load_recorder_file",
                 50:"exit",
                 61:"set_case_sensitive_labels",
                 106:"extended_select_look-up_table",
                 107:"extended_put_look-up_table",
                 108:"extended_get_look-up_table",
                 109:"extended_get_look-up_table_value",
                 110:"extended_increase_look-up_table",
                 111:"extended_set_look-up_table",
                 112:"extended_parameter_for_value_acquisition",
                 114:"extended_get_parameter",
                 115:"extended_set_parameter",
                 119:"extended_get_online_value",
                 200:"extended_query_available_services",
                 201:"extended_get_service_information",
                 202:"extended_execute_service",
                 }

def get_asap3_command_code_by_name(n):
    for x in ASAP3COMMANDS:
        if ASAP3COMMANDS[x] == n:
            return x
    raise ValueError("Not Found {0}".format(n))


class asap3error(Exception):
    def __init__(self, *args, **kwargs):
        super(asap3error,self).__init__(self, *args, **kwargs)

class asap3timeout(asap3error):
    def __init__(self, *args, **kwargs):
        super(asap3timeout,self).__init__(self, *args, **kwargs)

class asap3notimplemented(asap3error):
    def __init__(self, *args, **kwargs):
        super(asap3notimplemented,self).__init__(self, *args, **kwargs)


def create_asap3_string(s):
    bs = s.encode()
    ret = bytearray()
    ret.extend(struct.pack(">H",len(s)))
    ret.extend(bs)
    if len(bs) % 2:
        ret.append(0)
    return ret

def pop_asap3_string(data):
    L = struct.unpack(">H",data[:2])[0]
    if L % 2:
        L += 1
    return (str(asap3string(s=data[:2+L])),data[2+L:])
    

def create_asap3_message(cmd,status=None,data=None):
    assert(cmd != None)
    d = bytearray()
    d.extend(struct.pack(">H",cmd))
    if status:
        d.extend(struct.pack(">H",status))
    if data:
        if isinstance(data,str):
            d.extend(create_asap3_string(data))
        elif isinstance(data,bytearray):
            d.extend(data)
        elif isinstance(data,bytes):
            d.extend(data)
    ret = bytearray()
    ret.extend(struct.pack(">H",len(d)+4))
    ret.extend(d)
    ret.extend(struct.pack(">H",calc_checksum(ret)))
    return ret

def create_asap3_version(v):
    ret = bytearray()
    major,minor = [int(x) for x in str(v).split(".")]
    ret.extend(struct.pack("BB",major,minor))
    return ret
    
def interpret_asap3_message(data):
    l = struct.unpack(">H",data[:2])[0]
    assert (l == len(data))
    cs = calc_checksum(data[:-2])
    c = struct.unpack(">H",data[-2:])[0]
    assert(c == cs)
    cmd,stat = struct.unpack(">HH",data[2:6])
    d = data[6:-2]
    if d:
        da = d
    else:
        da = None
    return {"cmd":cmd,
            "status":stat,
            "data":da,
            }
    
def calc_checksum(data):
    checksum = 0
    for idx in range(0,len(data),2):
        checksum += struct.unpack(">H",data[idx:idx+2])[0]
    return checksum & 0xFFFF


class asap3string():
    def __init__(self,s):
        if isinstance(s,str):
            self.str = s
        elif isinstance(s,bytes) or isinstance(s,bytearray):
            self.from_bin(s)
            
    def to_bin(self):
        return create_asap3_string(self.str)

    def from_bin(self,s):
        L = struct.unpack(">H",s[:2])[0]
        try:
            self.str = s[2:2+L].decode()
        except UnicodeError:
            self.str = s[2:2+L].decode("latin9")
        return

    def __str__(self):
        return self.str

class asap3version():
    def __init__(self,version):
        if isinstance(version,float):
            self.version = version
        elif isinstance(version,bytes) or isinstance(version,bytearray):
            self.from_bin(version)

    def to_bin(self):
        major,minor = [int(x) for x in str(self.version).split(".")]
        ret = struct.pack("BB",major,minor)
        return ret

    def from_bin(self,b):
        self.version = float(b[0]+(b[1]/10))

    def __str__(self):
        return str(self.version)

    def __float__(self):
        return self.version

class asap3map():
    def __init__(self):
        pass
    
    def to_bin(self):
        pass
    
    def from_bin(self,b):
        pass

    def __str__(self):
        pass


class asap3message():
    def __init__(self,cmd,data):
        self.cmd = cmd
        self.data = data

    def to_bin(self):
        return create_asap3_message(cmd=self.cmd,data=self.data)


class asap3service():
    def __init__(self,cmd,data=None,timeout=None):
        self.cmd = get_asap3_command_code_by_name(cmd)
        self.request = asap3message(cmd=self.cmd,data=data)
        self.response = queue.Queue()
        self.timeout = timeout
        self.status = A3_INIT
        self.txtimestamp=None
        self.rxtimestamp=None
    
    def get_status(self):
        return self.status
    
    def set_status(self,status):
        self.status = status
        return
        
    def get_request(self):
        self.set_status(status=A3_REQ)
        self.txtimestamp = datetime.datetime.now()
        return self.request.to_bin()
        
    def feed_response(self,resp):
        if resp["cmd"] != self.cmd:
            raise NotImplementedError("get_response {0} but found {1}".format(self.cmd,resp["cmd"]))
        self.set_status(status=resp["status"])
        self.rxtimestamp = datetime.datetime.now()
        resp.update({"timestamp":self.rxtimestamp})
        if resp["status"] == A3_CMPL:
            self.response.put(self.feed_specific(resp))
        elif resp["status"] == A3_ERR:
            data = resp.pop("data")
            err_code = struct.unpack(">H",data[:2])[0]
            err_text = asap3string(data[2:])
            resp.update({"err_code":err_code,
                         "err_txt":err_text})
            self.response.put(resp)
        return
                
    def feed_specific(self,resp):
        return resp
    
    def get_response(self):
        resp = self.response.get(timeout=self.timeout)
        if not resp:
            raise asap3timeout("Timeout of service")
        elif "err_code" in resp:
            print("ERR {err_code} TXT {err_txt}".format_map(resp))
            raise asap3error("ERR {err_code} TXT {err_txt}".format_map(resp))
        return resp
    
    def is_complete(self):
        if self.status in (A3_CMPL,A3_ERR,A3_NONIMPL):
            return True
        else:
            return False

#basic communication services
class asap3emergency(asap3service):
    def __init__(self,event):
        data = bytearray()
        data.extend(struct.pack(">H",event))
        super(asap3emergency, self).__init__(cmd="emergency",data=data)
        

class asap3init(asap3service):
    def __init__(self):
        super(asap3init, self).__init__(cmd="init")


class asap3identify(asap3service):
    def __init__(self,version,description):
        data = bytearray()
        data.extend(create_asap3_version(v=version))
        data.extend(create_asap3_string(s=description))
        super(asap3identify, self).__init__(cmd="identify",data=data)

    def feed_specific(self,resp):
        data = resp.pop("data")
        v = asap3version(data[:2])
        d = asap3string(data[2:])
        resp.update({"version":v,
                     "description":d,
                    })
        return resp
        

class asap3exit(asap3service):
    def __init__(self):
        super(asap3exit, self).__init__(cmd="exit")



#configuration services
class asap3select_desc_and_bin(asap3service):
    def __init__(self,desc_file,bin_file,dest):
        data = bytearray()
        data.extend(create_asap3_string(s=desc_file))
        data.extend(create_asap3_string(s=bin_file))
        data.extend(struct.pack(">H",dest))        
        super(asap3select_desc_and_bin, self).__init__(cmd="select_description_file_and_binary_file",data=data)

    def feed_specific(self,resp):
        data = resp.pop("data")
        L = struct.unpack(">H",data[0:2])[0]
        resp.update({"Lun":L,
                    })
        return resp


class asap3define_desc_and_bin(asap3service):
    def __init__(self,desc_file,prog_file,cal_file,dest,mode):
        data = bytearray()
        data.extend(create_asap3_string(s=desc_file))
        data.extend(create_asap3_string(s=prog_file))
        data.extend(create_asap3_string(s=cal_file))
        data.extend(struct.pack(">H",dest))
        data.extend(struct.pack(">H",mode))        
        super(asap3define_desc_and_bin, self).__init__(cmd="define_description_and_binary_file",data=data)

    def feed_specific(self,resp):
        data = resp.pop("data")
        L = struct.unpack(">H",data[0:2])[0]
        d,data = pop_asap3_string(data=data[2:])
        p,data = pop_asap3_string(data=data)
        c,data = pop_asap3_string(data=data)
        resp.update({"Lun":L,
                     "desc_file":d,
                     "prog_file":p,
                     "cal_file":c,
                    })
        return resp


class asap3copy_bin(asap3service):
    def __init__(self,tgt,src,Lun):
        data = bytearray()
        data.extend(struct.pack(">HHH",tgt,src,Lun))
        super(asap3copy_bin, self).__init__(cmd="copy_binary_file",data=data)

    
class asap3change_bin_name(asap3service):
    def __init__(self,new_name,Lun):
        data = bytearray()
        data.extend(create_asap3_string(s=new_name))
        data.extend(struct.pack(">H",Lun))
        super(asap3change_bin_name, self).__init__(cmd="change_binary_filename",data=data)


class asap3select_lookup_table(asap3service):
    def __init__(self,Lun,map_name):
        data = bytearray()
        data.extend(struct.pack(">H",Lun))
        data.extend(create_asap3_string(s=map_name))
        super(asap3select_lookup_table, self).__init__(cmd="select_look-up_table",data=data)


    def feed_specific(self,resp):
        data = resp.pop("data")
        map_num,ny,nx,addr = struct.unpack(">HHHH",data[:8])
        resp.update({"map_number":map_num,
                     "y_number":ny,
                     "x_number":nx,
                     "address":addr,
                    })
        return resp


class asap3extended_select_lookup_table(asap3service):
    def __init__(self,Lun,map_name):
        data = bytearray()
        data.extend(struct.pack(">H",Lun))
        data.extend(create_asap3_string(s=map_name))
        super(asap3extended_select_lookup_table, self).__init__(cmd="extended_select_look-up_table",data=data)


    def feed_specific(self,resp):
        data = resp.pop("data")
        map_num,ny,nx,y_phys_data_type,x_phys_data_type,z_phys_data_type,y_ctl_data_type,x_ctl_data_type,z_ctl_data_type,addr = struct.unpack(">H"*9+"i",data)
        resp.update({"map_number":map_num,
                     "y_number":ny,
                     "x_number":nx,
                     "y_phys_data_type":y_phys_data_type,
                     "x_phys_data_type":x_phys_data_type,
                     "z_phys_data_type":z_phys_data_type,
                     "y_ctl_data_type":y_ctl_data_type,
                     "x_ctl_data_type":x_ctl_data_type,
                     "z_ctl_data_type":z_ctl_data_type,
                     "address":addr,
                    })
        return resp



class asap3get_lookup_table(asap3service):
    def __init__(self,map_number):
        data = bytearray()
        data.extend(struct.pack(">H",map_number))
        super(asap3get_lookup_table, self).__init__(cmd="get_look-up_table",data=data)


    def feed_specific(self,resp):
        data = resp.pop("data")
        map_length = struct.unpack(">H",data[:2])[0]
        fmt = ">"+"f"*map_length
        vals = struct.unpack(fmt,data[2:(2+(map_length*4))])
        
        resp.update({"map_length":map_length,
                     "vals":vals,
                    })
        return resp


class asap3put_lookup_table(asap3service):
    def __init__(self,map_number,vals):
        data = bytearray()
        map_length = len(vals)
        data.extend(struct.pack(">HH",map_number,map_length))
        fmt = ">"+"f"*map_length
        data.extend(struct.pack(fmt,*vals))
        super(asap3put_lookup_table, self).__init__(cmd="put_look-up_table",data=data)



class asap3get_lookup_table_value(asap3service):
    def __init__(self,map_number,y_idx,x_idx):
        data = bytearray()
        data.extend(struct.pack(">HHH",map_number,y_idx,x_idx))
        super(asap3get_lookup_table_value, self).__init__(cmd="get_look-up_table_value",data=data)

    def feed_specific(self,resp):
        data = resp.pop("data")
        val = struct.unpack(">f",data[:4])[0]
        resp.update({"val":val,
                    })
        return resp
        

class asap3increase_lookup_table(asap3service):
    def __init__(self,map_number,y_idx,x_idx,y_delta,x_delta,offset):
        data = bytearray()
        data.extend(struct.pack(">HHHHHf",map_number,y_idx,x_idx,y_delta,x_delta,offset))
        super(asap3increase_lookup_table, self).__init__(cmd="increase_look-up_table",data=data)


class asap3set_lookup_table(asap3service):
    def __init__(self,map_number,y_idx,x_idx,y_delta,x_delta,val):
        data = bytearray()
        data.extend(struct.pack(">HHHHHf",map_number,y_idx,x_idx,y_delta,x_delta,val))
        super(asap3set_lookup_table, self).__init__(cmd="set_look-up_table",data=data)


class asap3parameter_for_value_aquisition(asap3service):
    def __init__(self,Lun,sample_rate,val_names):
        data = bytearray()
        data.extend(struct.pack(">HHH",Lun,sample_rate,len(val_names)))
        for val in val_names:
            data.extend(create_asap3_string(s=val))
        super(asap3parameter_for_value_aquisition, self).__init__(cmd="parameter_for_value_acquisition",data=data)

class asap3switching_online_offline(asap3service):
    def __init__(self,mode):
        data = bytearray()
        data.extend(struct.pack(">H",mode))
        super(asap3switching_online_offline, self).__init__(cmd="switching_online_offline",data=data)



class asap3get_online_value(asap3service):
    def __init__(self):
        super(asap3get_online_value, self).__init__(cmd="get_online_value")

    def feed_specific(self,resp):
        data = resp.pop("data")
        L = struct.unpack(">H",data[0:2])[0]
        fmt = ">"+"f"*L
        vals = struct.unpack(fmt,data[2:])
        resp.update({"vals":vals,
                    })
        return resp
    
    
class asap3get_parameter(asap3service):
    def __init__(self,Lun,para_name):
        data = bytearray()
        data.extend(struct.pack(">H",Lun))
        data.extend(create_asap3_string(s=para_name))
        super(asap3get_parameter, self).__init__(cmd="get_parameter",data=data)
        
    def feed_specific(self,resp):
        data = resp.pop("data")
        val,val_min,val_max,min_inc = struct.unpack(">ffff",data)
        
        resp.update({"val":val,
                     "min":val_min,
                     "max":val_max,
                     "min_inc":min_inc,
                    })
        return resp
    

class asap3set_parameter(asap3service):
    def __init__(self,Lun,para_name,val):
        data = bytearray()
        data.extend(struct.pack(">H",Lun))
        data.extend(create_asap3_string(s=para_name))
        data.extend(struct.pack(">f",val))
        super(asap3set_parameter, self).__init__(cmd="set_parameter",data=data)

class asap3extended_get_parameter(asap3service):
    def __init__(self,Lun,para_name):
        data = bytearray()
        data.extend(struct.pack(">H",Lun))
        data.extend(create_asap3_string(s=para_name))
        super(asap3extended_get_parameter, self).__init__(cmd="extended_get_parameter",data=data)
        
    def feed_specific(self,resp):
        data = resp.pop("data")
        data_type = struct.unpack(">H",data[0:2])[0]
        if data_type == 0:
            fmt = ">"+"f"*4
            tp = "float"
            val,val_min,val_max,min_inc = struct.unpack(fmt,data[2:])
            resp.update({"val":val,
                         "min":val_min,
                         "max":val_max,
                         "min_inc":min_inc,
                        })

        elif data_type == 1:
            fmt = ">"+"d"*4
            tp = "double"
            val,val_min,val_max,min_inc = struct.unpack(fmt,data[2:])
            resp.update({"val":val,
                         "min":val_min,
                         "max":val_max,
                         "min_inc":min_inc,
                        })
            
        elif data_type == 2:
            fmt = None
            tp = "string"
            val,data = pop_asap3_string(data=data[2:])
            resp.update({"val":val,})
        
        return resp


class asap3extended_set_parameter(asap3service):
    def __init__(self,Lun,para_name,val,data_type=None):
        data = bytearray()
        data.extend(struct.pack(">H",Lun))
        data.extend(create_asap3_string(s=para_name))
        if not data_type:
            if isinstance(val,str):
                data_type = 2
            else:
                data_type = 0
        data.extend(struct.pack(">H",data_type))
        if data_type == 0:
            data.extend(struct.pack(">f",val))
        elif data_type == 1:
            data.extend(struct.pack(">d",val))
        elif data_type == 2:
            data.extend(create_asap3_string(s=val))
        super(asap3extended_set_parameter, self).__init__(cmd="extended_set_parameter",data=data)


class asap3set_graphic_mode(asap3service):
    def __init__(self,mode):
        data = bytearray()
        data.extend(struct.pack(">H",mode))
        super(asap3set_graphic_mode, self).__init__(cmd="set_graphic_mode",data=data)


class asap3reset_device(asap3service):
    def __init__(self,Lun):
        data = bytearray()
        data.extend(struct.pack(">H",Lun))
        super(asap3reset_device, self).__init__(cmd="reset_device",data=data)


class asap3set_case_sensitive_labels(asap3service):
    def __init__(self):
        super(asap3set_case_sensitive_labels, self).__init__(cmd="set_case_sensitive_labels")


class asap3define_recorder_parameters(asap3service):
    def __init__(self,Lun,rec_type,sample_rate,divider,val_names):
        data = bytearray()
        data.extend(struct.pack(">HHfHH",Lun,rec_type,sample_rate,divider,len(val_names)))
        for val in val_names:
            data.extend(create_asap3_string(s=val))
        super(asap3define_recorder_parameters, self).__init__(cmd="define_recorder_parameters",data=data)


class asap3define_trigger_condition(asap3service):
    def __init__(self,start_trigger,stop_trigger,sample_count,start_delay,stop_delay):
        data = bytearray()
        data.extend(create_asap3_string(s=start_trigger))
        data.extend(create_asap3_string(s=stop_trigger))
        data.extend(struct.pack(">III",sample_count,start_delay,stop_delay))
        super(asap3define_trigger_condition, self).__init__(cmd="define_trigger_condition",data=data)


class asap3activate_recorder(asap3service):
    def __init__(self,mode):
        data = bytearray()
        data.extend(struct.pack(">H",mode))
        super(asap3activate_recorder, self).__init__(cmd="activate_recorder",data=data)
        
        
class asap3get_recorder_status(asap3service):
    def __init__(self):
        super(asap3get_recorder_status, self).__init__(cmd="get_recorder_status")
        
    def feed_specific(self,resp):
        data = resp.pop("data")
        rec_status,sample_cnt,stop_cond = struct.unpack(">HIH",data[:8])
        stop_info,data = pop_asap3_string(data[8:])
        
        resp.update({"rec_status":rec_status,
                     "sample_cnt":sample_cnt,
                     "stop_cond":stop_cond,
                     "stop_info":stop_info,
                    })
        return resp


class asap3get_recorder_result_header(asap3service):
    def __init__(self):
        super(asap3get_recorder_result_header, self).__init__(cmd="get_recorder_result_header")
        
    def feed_specific(self,resp):
        data = resp.pop("data")
        
        starttime,data = pop_asap3_string(data)
        rec_type,sample_rate,divider,sample_cnt,start_delay,stop_delay,lost_samples_cnt,max_phase_error = struct.unpack(">HfHIIIII",data)
        resp.update({"starttime":starttime,
                     "rec_type":rec_type,
                     "sample_rate":sample_rate,
                     "divider":divider,
                     "sample_cnt":sample_cnt,
                     "start_delay":start_delay,
                     "stop_delay":stop_delay,
                     "lost_samples_cnt":lost_samples_cnt,
                     "max_phase_error":max_phase_error,
                    })
        return resp
    

class asap3get_recorder_results(asap3service):
    def __init__(self,sample_number):
        data = bytearray()
        data.extend(struct.pack(">I",sample_number))
        super(asap3get_recorder_results, self).__init__(cmd="get_recorder_results",data=data)
        
    def feed_specific(self,resp):
        data = resp.pop("data")
        sample_number,L = struct.unpack(">IH",data[0:6])
        fmt = ">"+"f"*L
        vals = struct.unpack(fmt,data[6:])
        resp.update({"sample_number":sample_number,
                     "vals":vals,
                    })
        return resp
    

class asap3save_recorder_file(asap3service):
    def __init__(self,fname):
        data = bytearray()
        data.extend(create_asap3_string(s=fname))
        super(asap3save_recorder_file, self).__init__(cmd="save_recorder_file",data=data)


class asap3load_recorder_file(asap3service):
    def __init__(self,fname):
        data = bytearray()
        data.extend(create_asap3_string(s=fname))
        super(asap3load_recorder_file, self).__init__(cmd="load_recorder_file",data=data)


    def feed_specific(self,resp):
        data = resp.pop("data")
        L = struct.unpack(">H",data[0:2])[0]
        val_names = []
        data = data[0:2]
        for i in range(L):
            val_name,data = pop_asap3_string(data=data)
            val_names.append(val_name)
        resp.update({"val_names":val_names
                    })
        return resp


class asap3extended_query_available_services(asap3service):
    def __init__(self):        
        super(asap3extended_query_available_services, self).__init__(cmd="extended_query_available_services")

    def feed_specific(self,resp):
        data = resp.pop("data")
        L = struct.unpack(">H",data[0:2])[0]
        data = data[2:]
        vals = []
        for i in range(L):
            val,data = pop_asap3_string(data=data)
            vals.append(val)    
        resp.update({"vals":vals,
                    })
        return resp


class asap3extended_get_service_information(asap3service):
    def __init__(self,service):
        data = bytearray()
        data.extend(create_asap3_string(s=service))
        super(asap3extended_get_service_information, self).__init__(cmd="extended_get_service_information",data=data)

    def feed_specific(self,resp):
        data = resp.pop("data")
        info,data = pop_asap3_string(data=data)
        resp.update({"info":info,
                    })
        return resp


class asap3extended_execute_service(asap3service):
    def __init__(self,service,service_input_parameter):
        data = bytearray()
        data.extend(create_asap3_string(s=service))
        data.extend(create_asap3_string(s=service_input_parameter))
        super(asap3extended_execute_service, self).__init__(cmd="extended_execute_service",data=data)

    def feed_specific(self,resp):
        data = resp.pop("data")
        sop,data = pop_asap3_string(data=data)
        resp.update({"service_output_parameter":sop,
                    })
        return resp


        

class asap3client:
    def __init__(self,host=None,port=None,timeout=30):
        self._init_logger()
        self.host = None
        self.port = None
        self.con = None
        self.timeout = timeout
        self.rxbuffer = bytearray()
        
        if host:
            self.host = host
        if port:
            self.port = port
            
        
        self.implemented_asap_version = ASAP3VERSION
        self.description = "python3 client for ASAP3 V{0}".format(ASAP3CLIENTVERSION)
        
        self.remote_server_description = None
        self.remote_server_asap_version = None

        self.rx_queue = queue.Queue()
        self.rx_handler = threading.Thread(target=self.handlerx)
        self.rx_handler.setDaemon(True)
        
        self.requests = queue.Queue()
        self.request_handler = threading.Thread(target=self.handlerequests)
        self.request_handler.setDaemon(True)
        self.currentrequest = None
        
        if (self.host != None) and (self.port != None):
            self.connect_to_host(host=self.host,port=self.port)

        self._log_debug('Init complete')

    def _init_logger(self):
        self._logger = logging.getLogger('asap3client')
        self._logger.setLevel(logging.DEBUG)
        self._fh = logging.FileHandler('asap3client.log')
        #self._fh.setLevel(logging.DEBUG)
        self._fh.setLevel(logging.INFO)
        #self._fh.setLevel(logging.ERROR)
        self._ch = logging.StreamHandler()
        self._ch.setLevel(logging.ERROR)
        self._formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self._fh.setFormatter(self._formatter)
        self._ch.setFormatter(self._formatter)
        self._logger.addHandler(self._fh)
        self._logger.addHandler(self._ch)
        self._log_debug('Logger has been initialized')
        return
    
    def _log_info(self,msg):
        if self._logger:
            self._logger.info(msg)
        return
                
    def _log_error(self,msg):
        if self._logger:
            self._logger.error(msg)
        return
    
    def _log_debug(self,msg):
        if self._logger:
            self._logger.debug(msg)
        return
    
    def get_remote_server_data(self):
        return (self.remote_server_description,
                self.remote_server_asap_version)
    
    def transmit(self,msg):
        self._log_debug("SND: {0}".format(" ".join(["{0:02X}".format(x) for x in msg])))
        return self.con.sendall(msg)

    def connect_to_host(self,host,port):
        self.con = socket.create_connection(address=(host,port))
        self.rx_handler.start()
        self.request_handler.start()
        resp = self.a3init()
        if resp["status"] == 0:
            resp = self.a3identify()
            if resp["status"] == 0:
                self._log_info("Server:{description}, Version:{version}".format_map(resp))
                self.remote_server_description = str(resp["description"])
                self.remote_server_asap_version = float(resp["version"])
                assert (self.remote_server_asap_version == self.implemented_asap_version)
            
        return

    def disconnect_from_host(self):
        self._log_info("Disconnecting from Server")
        self.a3exit()
        self.con.close()
        self.con = None
        return
    
    def handlerequests(self):
        assert(self.con != None)
        while (self.con != None):
            self.currentrequest = self.requests.get()
            self.transmit(self.currentrequest.get_request())
            while not self.currentrequest.is_complete():
                self.currentrequest.feed_response(self.rx_queue.get(timeout=self.timeout))
        return None

    def handlerx(self):
        assert(self.con != None)        
        while (self.con != None):
            try:
                data = self.con.recv(2)
            except ConnectionAbortedError:
                break
            if len(data) == 2:
                self.rxbuffer.extend(data)
                l = struct.unpack(">H",data)[0]
                data = self.con.recv(l-2)
                self.rxbuffer.extend(data)
                self._log_debug("RCV: {0}".format(" ".join(["{0:02X}".format(x) for x in data])))
                msg = interpret_asap3_message(self.rxbuffer)
                if msg:
                    self.rx_queue.put(msg)
                    self.rxbuffer.clear()       
            else:
                time.sleep(1)
        return None
    
    def request_service(self,s):
        self.requests.put(s)
        resp = s.get_response()
        return resp
    
    #standard asap3 commands follow
                
    def a3init(self):
        self._log_debug("a3init")
        return self.request_service(s=asap3init())

    def a3identify(self):
        self._log_debug("a3identify")
        return self.request_service(s=asap3identify(version=self.implemented_asap_version,description=self.description))
 
    def a3exit(self):
        self._log_debug("a3exit")
        return self.request_service(s=asap3exit())

    def a3emergency(self,event=0):
        self._log_debug("a3emergency w event {0}".format(event))
        return self.request_service(s=asap3emergency(event=event))

    def a3select_desc_and_bin(self,desc_file,bin_file,dest):
        self._log_debug("a3select_desc_and_bin w desc_file {0} bin_file {1} dest {2}".format(desc_file,bin_file,dest))
        return self.request_service(s=asap3select_desc_and_bin(desc_file=desc_file,
                                                               bin_file=bin_file,
                                                               dest=dest))

    def a3define_desc_and_bin(self,desc_file,prog_file="",cal_file="",dest=0,mode=0):
        self._log_debug("a3define_desc_and_bin w desc_file {0} prog_file {1} cal_file {2} dest {3} mode {4}".format(desc_file,prog_file,cal_file,dest,mode))
        return self.request_service(s=asap3define_desc_and_bin(desc_file=desc_file,
                                                               prog_file=prog_file,
                                                               cal_file=cal_file,
                                                               dest=dest,
                                                               mode=mode))



    def a3copy_bin(self,tgt=2,src=4,Lun=0):
        self._log_debug("a3copy_bin w tgt {0} src {1} Lun {2}".format(tgt,src,Lun))
        return self.request_service(s=asap3copy_bin(tgt=tgt,
                                                    src=src,
                                                    Lun=Lun))

    def a3change_bin_name(self,new_name,Lun=0):
        self._log_debug("a3change_bin_name w new_name {0} Lun {1}".format(new_name,Lun))
        return self.request_service(s=asap3change_bin_name(new_name=new_name,Lun=Lun))

    def a3select_lookup_table(self,Lun,map_name):
        self._log_debug("a3select_lookup_table w Lun {0} map_name {1}".format(Lun,map_name))
        return self.request_service(s=asap3select_lookup_table(Lun=Lun,map_name=map_name))
    
    def a3get_lookup_table(self,map_number):
        self._log_debug("a3get_lookup_table w map_number {0}".format(map_number))
        return self.request_service(s=asap3get_lookup_table(map_number=map_number))

    def a3put_lookup_table(self,map_number,vals):
        self._log_debug("a3put_lookup_table w map_number {0} vals {1}".format(map_number,vals))
        return self.request_service(s=asap3put_lookup_table(map_number=map_number,vals=vals))

    def a3get_lookup_table_value(self,map_number,y_idx,x_idx):
        self._log_debug("a3get_lookup_table_value w map_number {0} y_idx {1} x_idx {2}".format(map_number,y_idx,x_idx))
        return self.request_service(s=asap3get_lookup_table_value(map_number=map_number,y_idx=y_idx,x_idx=x_idx))

    def a3increase_lookup_table_value(self,map_number,y_idx,x_idx,y_delta,x_delta,offset):
        self._log_debug("a3increase_lookup_table_value w map_number {0} y_idx {1} x_idx {2} y_delta {3} x_delta {4} offset {5}".format(map_number,y_idx,x_idx,y_delta,x_delta,offset))
        return self.request_service(s=asap3increase_lookup_table(map_number=map_number,y_idx=y_idx,x_idx=x_idx,y_delta=y_delta,x_delta=x_delta,offset=offset))

    def a3set_lookup_table_value(self,map_number,y_idx,x_idx,y_delta,x_delta,val):
        self._log_debug("a3set_lookup_table_value w map_number {0} y_idx {1} x_idx {2} y_delta {3} x_delta {4} offset {5}".format(map_number,y_idx,x_idx,y_delta,x_delta,val))
        return self.request_service(s=asap3set_lookup_table(map_number=map_number,y_idx=y_idx,x_idx=x_idx,y_delta=y_delta,x_delta=x_delta,val=val))
        
    def a3parameter_for_value_aquisition(self,Lun,sample_rate,val_names):
        self._log_debug("a3parameter_for_value_aquisition w Lun {0} sample_rate {1} vals {2}".format(Lun,sample_rate,val_names))
        return self.request_service(s=asap3parameter_for_value_aquisition(Lun=Lun,sample_rate=sample_rate,val_names=val_names))

    def a3switching_online_offline(self,mode):
        self._log_debug("a3switching_online_offline w mode {0}".format(mode))
        return self.request_service(s=asap3switching_online_offline(mode=mode))
    
    def a3get_online_values(self):
        self._log_debug("a3get_online_values")
        return self.request_service(s=asap3get_online_value())
    
    def a3get_parameter(self,Lun, para_name):
        self._log_debug("a3get_parameter w Lun {0} para_name {1}".format(Lun,para_name))
        return self.request_service(s=asap3get_parameter(Lun=Lun, para_name=para_name))

    def a3set_parameter(self,Lun, para_name, val):
        self._log_debug("a3set_parameter w Lun {0} para_name {1} val {2}".format(Lun,para_name,val))
        return self.request_service(s=asap3set_parameter(Lun=Lun, para_name=para_name, val=val))

    def a3set_graphic_mode(self,mode):
        self._log_debug("a3set_graphic_mode")
        return self.request_service(s=asap3set_graphic_mode(mode=mode))
    
    def a3reset_device(self,Lun):
        self._log_debug("a3reset_device w Lun {0}".format(Lun))
        return self.request_service(s=asap3reset_device(Lun=Lun))
    
    def a3set_case_sensitive_labels(self):
        self._log_debug("a3set_case_sensitive_labels")
        return self.request_service(s=asap3set_case_sensitive_labels())

    def a3define_recorder_parameters(self,Lun,rec_type,sample_rate,divider,val_names):
        self._log_debug("a3define_recorder_parameters")
        return self.request_service(s=asap3define_recorder_parameters(Lun=Lun,rec_type=rec_type,sample_rate=sample_rate,divider=divider,val_names=val_names))

    def a3define_trigger_condition(self,start_trigger,stop_trigger,sample_count,start_delay,stop_delay):
        self._log_debug("a3define_trigger_condition")
        return self.request_service(s=asap3define_trigger_condition(start_trigger=start_trigger,stop_trigger=stop_trigger,sample_count=sample_count,start_delay=start_delay,stop_delay=stop_delay))

    def a3activate_recorder(self,mode):
        self._log_debug("a3activate_recorder w mode {0}".format(mode))
        return self.request_service(s=asap3activate_recorder(mode=mode))

    def a3get_recorder_status(self):
        self._log_debug("a3get_recorder_status")
        return self.request_service(s=asap3get_recorder_status())

    def a3get_recorder_result_header(self):
        self._log_debug("a3get_recorder_result_header")
        return self.request_service(s=asap3get_recorder_result_header())

    def a3get_recorder_results(self,sample_number):
        self._log_debug("a3get_recorder_results")
        return self.request_service(s=asap3get_recorder_results(sample_number=sample_number))

    def a3save_recorder_file(self,fname):
        self._log_debug("a3save_recorder_file")
        return self.request_service(s=asap3save_recorder_file(fname=fname))
    
    def a3load_recorder_file(self,fname):
        self._log_debug("a3load_recorder_file")
        return self.request_service(s=asap3load_recorder_file(fname=fname))

    #extended (optional) asap3 commands follow

    def a3extended_select_lookup_table(self,Lun,map_name):
        self._log_debug("a3a3extended_select_lookup_table w Lun {0} map_name {1}".format(Lun,map_name))
        return self.request_service(s=asap3extended_select_lookup_table(Lun=Lun,map_name=map_name))


    def a3extended_get_parameter(self,Lun, para_name):
        self._log_debug("a3extended_get_parameter w Lun {0} para_name {1}".format(Lun,para_name))
        return self.request_service(s=asap3extended_get_parameter(Lun=Lun, para_name=para_name))
    
    def a3extended_set_parameter(self,Lun, para_name, val, data_type=None):
        self._log_debug("a3extended_set_parameter w Lun {0} para_name {1} val {2}".format(Lun,para_name,val))
        return self.request_service(s=asap3extended_set_parameter(Lun=Lun, para_name=para_name, val=val, data_type=data_type))

    
    def a3extended_query_available_services(self):
        self._log_debug("a3extended_query_available_services")
        return self.request_service(s=asap3extended_query_available_services())
    
    def a3extended_get_service_information(self,service):
        self._log_debug("a3extended_get_service_information w service {0}".format(service))
        return self.request_service(s=asap3extended_get_service_information(service=service))

    def a3extended_execute_service(self,service,service_input_parameter):
        self._log_debug("a3extended_execute_service w service {0} service_input_parameter {1}".format(service,service_input_parameter))
        return self.request_service(s=asap3extended_execute_service(service=service,service_input_parameter=service_input_parameter))

    

    #convenience functions for users

    def get_map_vals_by_name(self,map_name,Lun=0):
        self._log_debug("get_map_vals_by_name w map_name {0} Lun {1}".format(map_name, Lun))
        desc_resp  = self.a3select_lookup_table(Lun=Lun,map_name=map_name)
        map_number = desc_resp["map_number"]
        nx = desc_resp["x_number"]
        ny = desc_resp["y_number"]
        addr = desc_resp["address"]
        data_resp = self.a3get_lookup_table(map_number=map_number)
        vals = list(data_resp["vals"])
        ys = []
        xs = []
        for i in range(ny):
            ys.append(vals.pop(0))
        for i in range(nx):
            xs.append(vals.pop(0))
        z_min = vals.pop(0)
        z_max = vals.pop(0)
        min_inc = vals.pop(0)
        zs = vals
        zsl = len(zs)
        ezsl = nx*ny
        if zsl != ezsl:
            raise ValueError("Incorrect Length of Z Values {0} but should be {1}".format(zsl,ezsl))
        return {"x_vals":xs,
                "y_vals":ys,
                "z_vals":zs,
                "z_max":z_max,
                "z_min":z_min,
                "min_inc":min_inc,
                "map_number":map_number,
                "x_number":nx,
                "y_number":ny,
                "address":addr,
                }

    def set_map_vals_by_name(self,map_name,x_vals,z_vals,y_vals=None,Lun=0):
        self._log_debug("get_map_vals_by_name w map_name {0} x_vals {1} y_vals {2} z_vals {2} Lun {3}".format(map_name,x_vals,z_vals,y_vals,Lun))
        resp  = self.get_map_vals_by_name(map_name=map_name,Lun=Lun)
        map_number = resp["map_number"]
        nx = resp["x_number"]
        ny = resp["y_number"]
        addr = resp["address"]
        z_max = resp["z_max"]
        z_min = resp["z_min"]
        min_inc = resp["min_inc"]

        if len(x_vals) != nx:
            raise ValueError("X_Vals")
        if y_vals:
            if len(y_vals) != ny:
                raise ValueError("Y_Vals")
        if len(z_vals) != (ny*nx):
            raise ValueError("Z_Vals")
                    
        vals = []
        if ny > 1:
            if not y_vals:
                raise ValueError("Map expects more than one")
            vals.extend(y_vals)    
        else:
            vals.append(0)
        vals.extend(x_vals)
        vals.extend((z_min,z_max,min_inc))
        vals.extend(z_vals)

        resp = self.a3put_lookup_table(map_number=map_number,vals=vals)
        return resp
    
    def switch_online(self):
        return self.a3switching_online_offline(mode=1)
    
    def switch_offline(self):
        return self.a3switching_online_offline(mode=0)
    
    def record_online_values(self,Lun,val_names,sample_rate,duration):
        try:
            resp = self.a3parameter_for_value_aquisition(Lun=Lun, sample_rate=sample_rate, val_names=val_names)
        except asap3error:
            self._log_error("read_online_values failed at parameter_for_value_aquisition {status},{err_code},{err_txt}".format_map(resp))
        
        try:
            self.switch_online()
        except asap3error:
            self._log_error("read_online_values failed at switch_online {status},{err_code},{err_txt}".format_map(resp))
        else:
            endtime = time.time()+duration
            online_vals = []
            while time.time() < endtime:
                try: 
                    resp = self.a3get_online_values()
                except asap3error:
                    self._log_error("read_online_values failed at get_online_values {status},{err_code},{err_txt}".format_map(resp))
                    break
                else:
                    v = resp["vals"]
                    online_vals.append(v)
                    time.sleep(sample_rate/1000)
                    
            
            try:
                self.switch_offline()
            except asap3error:
                self._log_error("read_online_values failed at switch_offline {status},{err_code},{err_txt}".format_map(resp))
        
        val_dict = {}
        for idx,val_name in enumerate(val_names):
            val_dict.update({val_name:[online_vals[i][idx] for i in range(len(online_vals))]})
        return val_dict
    
    
    def remote_record_values(self,Lun,val_names,rec_type=0,sample_rate=100,divider=0,trigger_condition_start="",start_trigger="",stop_trigger="",sample_count=0,start_delay=0,stop_delay=0,fname="",duration=None):
        if duration:
            sample_count = int(duration*1000 / sample_rate)
        resp = self.a3define_recorder_parameters(Lun=Lun,rec_type=rec_type,sample_rate=sample_rate,divider=divider,val_names=val_names)
        
        resp = self.a3define_trigger_condition(start_trigger=start_trigger,stop_trigger=stop_trigger,sample_count=sample_count,start_delay=start_delay,stop_delay=stop_delay)

        self.switch_online()
        resp = self.a3activate_recorder(mode=1)
        if not start_trigger:
            resp = self.a3activate_recorder(mode=2)
        
        recording_finished = False
        while not recording_finished:
            print("waiting for recorder to finish")
            time.sleep(1)
            resp = self.a3get_recorder_status()
            recording_finished = (resp["rec_status"] == 2)
        
        resp = self.a3activate_recorder(mode=0)
        self.switch_offline()
        if fname:
            resp = self.a3save_recorder_file(fname=fname)
        
        resp = self.a3get_recorder_result_header()
        sample_cnt = resp["sample_cnt"]
        record_vals = []
        for i in range(1,sample_cnt+1):
            resp = self.a3get_recorder_results(sample_number=i)
            vals = resp["vals"]
            record_vals.append(vals)
        val_dict = {}
        for idx,val in enumerate(val_names):
            val_dict.update({val:[record_vals[i][idx] for i in range(len(record_vals))]})
        return val_dict
    
    
    
def selftest(testmode="object"):
    HOST = "127.0.0.1"
    PORT = 22222

    if testmode == "object":
        mya3client = asap3client(host=HOST,port=PORT)
        remote_server_desc = mya3client.get_remote_server_data()[0].upper()
        print(remote_server_desc)
        mya3client.disconnect_from_host()
            
if __name__ == "__main__":
    selftest(testmode="object")    


