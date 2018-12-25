import re

def SegStartByName(name):
    return get_segm_start(get_segm_by_sel(selector_by_name(name)))

def SegsByName(name):
    ret = []
    segbase = get_first_seg()
    while segbase != BADADDR:
        if get_segm_name(segbase) == name:
            ret.append(segbase)
        segbase = get_next_seg(segbase)
    return ret

def HasRefTo(addr):
    return get_first_cref_to(addr) != BADADDR or get_first_dref_to(addr) != BADADDR

def MinEA():
    return get_inf_attr(INF_MIN_EA)

def MaxEA():
    return get_inf_attr(INF_MAX_EA)

# recognize some hidden pointers
def SearchIn(segname):
    global cnt
    min = MinEA()
    max = MaxEA()
    segs = SegsByName(segname)
    for segStart in segs:
        segEnd = get_segm_end(segStart)
        # first scan, make qword
        pattern = re.compile(r"dq\s+offset")
        for addr in range(segStart, segEnd, 8):
            if pattern.search(generate_disasm_line(addr, 0)):
                continue
            value = get_qword(addr)
            if value >= min and value <= max:   # a suspicious address
                # if there is no Xref to this, then it must be a pointer
                if HasRefTo(addr+2):
                    continue
                if HasRefTo(addr+4):
                    continue
                if HasRefTo(addr+6):
                    continue
                del_items(addr, 0, 8)
                create_qword(addr)
                cnt+=1
        # second scan, make vtbl
        pattern = re.compile(r"dq\s+offset\s+(\w+)")
        cnt = 0
        vtbl = []
        classname = ''
        typemap = {}
        for addr in range(segStart, segEnd, 8):
            m = pattern.search(generate_disasm_line(addr, 0))
            if m:
                name = m.group(1)
                dname = demangle_name(name, 0)
                if dname != None:
                    name = dname
                if name == None:
                    print 'Error at %x'%addr
                if name.find('::') != -1 and name.find('(') != -1:
                    cnt += 1
                    splt = name.split('::')
                    classname = splt[0]
                    funcname = splt[-1].split('(')[0].replace('~','Destruct')
                    vtbl.append(funcname)
                elif name.find('pure_virtual') != -1:
                    cnt += 1
                    vtbl.append('pure_virtual_'+str(cnt))
            else:
                if cnt != 0:
                    cnt = 0
                    if classname != '' and len(vtbl) > 0:
                        typename = classname + "Vtbl"
                        if typename in typemap:
                            typemap[typename] += 1
                            typename += str(typemap[typename])
                        else:
                            typemap[typename] = 1
                        sid = add_struc(-1, typename, 0)
                        funcmap = {}
                        for fn in vtbl:
                            if fn in funcmap:
                                funcmap[fn] += 1
                                fn += str(funcmap[fn])
                            else:
                                funcmap[fn] = 1
                            add_struc_member(sid, fn, -1, (FF_QWRD|FF_DATA), -1, 8)
                    classname = ''
                    vtbl = []
        for type in typemap:
            print type + " has been create."


SearchIn('__const')

