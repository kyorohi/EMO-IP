# ==============================================================================
# EMO-IP (エモ・アイピー)
# Creater:Kyorohi (Twitter:@kyorohi_kyorohi)
# v1.0:E.dll_v202303専用
# ==============================================================================

import numpy as np
import re
import json

c2ip_decrypt_func_patt = ["48 8D 05 ?? ?? ?? ?? 48 89"]


# ==============================================================================
# textセクションの開始と終了のアドレスを取得する関数
# ==============================================================================
def get_text_section_addr():
	#C2IPの情報は textセクションにあることが分かっているので、textセクションの開始と終了のアドレスを取得する。
    section_start = get_segm_by_sel(idc.selector_by_name(".text"))
    section_end = get_segm_end(section_start)#get_segm_end:終了アドレスを取得
    return section_start, section_end

 
# ==============================================================================
# C2IP復号関数の中から暗号化されたIPアドレスとポート番号を見つけて復号する関数
# ==============================================================================
def c2ip_decrypt(func_addr):

    Status = 0 
    ip = "x"
    port = "x"
    ip_b = []

    for ea in idautils.FuncItems(func_addr):

        if print_insn_mnem(ea) == "xor" and \
            get_operand_type(ea, 0) == o_reg and \
            get_operand_type(ea, 1) == o_reg and \
            idc.print_operand(ea, 0) != idc.print_operand(ea, 1):
                Key_Addr = ida_bytes.prev_head(ea,1)        
                Data_Addr = ida_bytes.prev_head(Key_Addr,1)

                if print_insn_mnem(Key_Addr) == "mov" and \
                    get_operand_type(Key_Addr, 0) == o_reg and \
                    (get_operand_type(Key_Addr, 1) == o_phrase or get_operand_type(Key_Addr, 1) == o_displ) and \
                    print_insn_mnem(Data_Addr) == "mov" and \
                    get_operand_type(Data_Addr, 0) == o_reg and \
                    (get_operand_type(Data_Addr, 1) == o_phrase or get_operand_type(Data_Addr, 1) == o_displ):

                        Key_Mark = idc.print_operand(Key_Addr,1)
                        Data_Mark = idc.print_operand(Data_Addr,1)
                        addr = Data_Addr
                        Data = 0
                        Key = 0
                       
                        while addr != func_addr:
                            addr = idc.prev_head(addr)

                            if Data_Mark == idc.print_operand(addr,0):
                                Data = get_operand_value(addr,1) & 0xFFFFFFFF

                            elif Key_Mark == idc.print_operand(addr,0):
                                Key = get_operand_value(addr,1) & 0xFFFFFFFF

                            if Data and Key:

                                Data = Data ^ Key

                                if Data == 0:
                                    return 0, 0

                                Data = format(Data,'x')

                                if len(Data) == 6:
                                    Data = '00'+ Data
                                    
                                elif len(Data) == 7:
                                    Data = '0'+ Data
                                
                                if Status == 0:

                                    for i in range(0,8,2):
                                        ip_a = Data[i:i+2]
                                        ip_b.append(int(ip_a,16))
            
                                    ip = '%d.%d.%d.%d' % (ip_b[3], ip_b[2], ip_b[1], ip_b[0])

                                    Status = 1

                                    set_cmt(ea, ip, 1)
                                    break

                                elif Status == 1:
                                    
                                    port_a = Data[0:4]
                                    port_b = int(port_a,16)
                                    port = str(port_b)

                                    set_cmt(ea, port, 1)

                                    break
    return ip, port


# ==============================================================================
# C2IP復号関数を探す関数
# ==============================================================================
def c2ip_search_decrypt_func(section_start, section_end):

    c2ip_buf = []
    c2ip_func = 0
    match_addr = 0

    data_list = np.empty((0,3), dtype="U13")
    
    for func in idautils.Functions(section_start, section_end):

        flags = get_func_attr(func, FUNCATTR_FLAGS)
        if flags & (FUNC_LIB | FUNC_THUNK):
            continue

        func_addr_end = idc.get_func_attr(func, FUNCATTR_END)

        for ea in idautils.FuncItems(func):

            if ea > match_addr:

                count = 0

                while count < len(c2ip_decrypt_func_patt):

                    patterns = ida_bytes.compiled_binpat_vec_t()
                    encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
                    err = ida_bytes.parse_binpat_str(patterns, ea, c2ip_decrypt_func_patt[count], 16, encoding)

                    if not err:
                        find_addr = ida_bytes.bin_search3(
                                ea,
                                func_addr_end,
                                patterns,
                                ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW)

                        if find_addr[0] != ida_idaapi.BADADDR:
                            match_addr = find_addr[0]

                            c2ip_decrypt_func_addr = idc.get_operand_value(find_addr[0],1)
		                    
                            ip, port = c2ip_decrypt(c2ip_decrypt_func_addr)
                            
                            if ip != "x" and port != "x":
                                change_name = "C2IP_" + str(ip) + "_" + str(port)
                                ida_name.set_name(c2ip_decrypt_func_addr, change_name, 0)

                                offset = idc.print_operand(idc.next_head(find_addr[0]),0)      
                                ptn = re.compile(r"(rbp|rsp)\+\w{2,3}h\+(var|arg)_(\w{2,3})")

                                if result := ptn.search(offset):

                                    index = str(int(result.group(3), 16))
                                    
                                    input_data = np.empty(3, dtype="U13")
                                    input_data[0] = index
                                    input_data[1] = ip
                                    input_data[2] = port

                                    data_list = np.append(data_list, [input_data], axis=0)

                            break
                        else:
                            count = count + 1

    sorted_data_list = data_list[data_list[:, 0].astype(int).argsort()[::-1]]

    return sorted_data_list

# ==============================================================================
# IPアドレスをソートする関数
# ==============================================================================
def c2ip_ip_sort(ip_address):

    ip, port = ip_address.split(':')
    octets = ip.split('.')

    return [int(octet) for octet in octets]


# ==============================================================================
# C2IPリストから実際に使用される情報だけリストに保存する関数
# ==============================================================================
def c2ip_extract(c2ip_list):

    c2ip_list2 = set()

    for i in range(len(c2ip_list)):
        if c2ip_list[i][1]!="0" and c2ip_list[i][2]!="0":
            c2ip_string = c2ip_list[i][1] + ":" + c2ip_list[i][2]
            c2ip_list2.add(c2ip_string)

        else:
            break
         
    c2ip_list2 = list(c2ip_list2)
  
    c2ip_list2_sorted = sorted(c2ip_list2,key=c2ip_ip_sort)

    return c2ip_list2_sorted


# ==============================================================================
# C2IP復号処理をまとめた関数
# ==============================================================================
def c2ip_main():

    section_start, section_end = get_text_section_addr() 

    c2ip_list = c2ip_search_decrypt_func(section_start, section_end)  

    c2ip_list2 = c2ip_extract(c2ip_list)

    return c2ip_list2


# ==============================================================================
# メイン関数
# ==============================================================================
def main():

    data_info = {}
    
    print("EMO-IP START")

    c2ip = c2ip_main()

    if c2ip:

        data_info['c2ip'] = c2ip
    else:
        print("no c2ip were found")

    data_info_path = ask_file(1, "*.json", "choose where to save decrypted info")
    json.dump(data_info, open(data_info_path, 'w'), indent=6, sort_keys=True)

    print("EMO-IP END")


if __name__ == '__main__':
    main()