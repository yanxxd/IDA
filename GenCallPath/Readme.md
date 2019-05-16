原文 [利用IDA Python静态分析函数调用路径](https://blog.51cto.com/watertoeast/2287039?source=dra)
代码没有实验过, 备份一下

# 强制转换未解析的代码. 针对RISC指令系统的
考虑到MIPS的指令均为32bit. 可利用IDAPython遍历指定的地址空间，把未定义的部分全部转换成代码。具体的代码如下：

```python
def define_func(beg, end):

    cur = beg

    if beg%4 != 0:
        cur = beg + 4 - beg%4 # 对齐

    end = end - end%4

    while cur < end:

        if ida_kernwin.user_cancelled():
            print('Cancelled')
            break

        cur_func = ida_funcs.get_func(cur)
        print("cur 0x%08x" % cur)

        if cur_func is None:

            if ida_funcs.add_func(cur):
                cur = ida_funcs.get_func(cur).endEA

            else:
                cur = cur + 4

        else:
            cur = cur_func.endEA
```
使用时步骤如下：

1、按shift+f2，在Execute script窗口中，Script language选择Python  
2、把上述代码粘贴到Please enter script body中  
3、点击Run，关闭Execute script窗口。  
4、在Output window下方的Python【IDC】按钮右侧，执行define_func(addr_start, addr_end)  

# 获取函数调用树
1、正向调用树
正向调用树以指定函数为起点，根据指定递归深度，获取其所有子函数，通常应用于跟踪用户输入数据的流向。实现思路如下：遍历指定函数（由参数指定）代码，如果当前指令为函数调用，则递归，直到达到递归深度或者没有子函数的函数。具体代码如下：

```python
import idautils

call_chain = [] # 存放正向调用链信息

def gen_call_chain(func_name, osintneting):

    del call_chain[:]
    f_call_out = open('d:\\call.csv', 'w')
    get_my_callee(func_name, osintneting, f_call_out)
    f_call_out.close()


def get_my_callee(func_name, osintneting, fl):
#print('call %s %d' % (func_name, osintneting))

    if ida_kernwin.user_cancelled():

        print('Cancelled')
        fl.close()
        exit()

    str = '{0}\t'.format(func_name)
    call_chain.append(str)
    addr = get_name_ea(0, func_name)

    # 获取所有子函数
    dism_addr = list(idautils.FuncItems(addr))
    xref_froms = []

    for ea in dism_addr:

        if ida_idp.is_call_insn(ea) is False:
            continue

        else:
            callee = get_first_fcref_from(ea)
            if callee != addr:
                xref_froms.append(callee)

    xref_froms = set(xref_froms)

    # 嵌套结束条件
    osinteneting_end = False

    if len(xref_froms) == 0:
        osinteneting_end = True

    elif osintneting == -1:
        osinteneting_end = False

    elif osintneting == 1:
        osinteneting_end = True

    if osinteneting_end is True:

        for callee in call_chain:
            sys.stdout.write(callee)
            fl.write(callee)

        sys.stdout.write('\r\n')
        fl.write('\r\n')

        call_chain.pop()
        return

    # 深度优先

    for xref_from in xref_froms:

        callee_name = get_func_name(xref_from)

        if osintneting == -1:
            get_my_callee(callee_name, -1, fl)

        else:
            get_my_callee(callee_name, osintneting - 1, fl)

    call_chain.pop()
```
参照上一节中的方法，调用gen_call_chain函数即可。gen_call_chain函数的第一个参数是函数名，第二参数是递归的次数限制，如果为-1，则会一直递归到叶子函数（无子函数的函数）

Python>gen_call_chain('start', 5)  
start sub_4010E0 sub_400DD0 sub_401B40 sub_401B80  
start sub_4010E0 sub_400DD0 sub_401B40 sub_401A00  
start sub_4010E0 sub_400DD0 sub_444750 sub_472EB0  
......

# 反向调用树
反向调用树以指定函数为起点，根据指定递归深度，获取其所有父函数，通常应用于跟踪危险函数被调用的路径。实现思路如下：先获取引用指定函数（由参数指定）的函数，然后依次递归，直到达到递归深度或者没有父函数的函数。具体代码如下：
```python
import idautils

r_call_chain = [] # 存放反向调用链信息

def gen_r_call_chain(func_name, osintneting):

    del r_call_chain[:]
    f_r_call_out = open('d:\\r_call.csv', 'w')
    get_my_caller(func_name, osintneting, f_r_call_out)
    f_r_call_out.close()


def get_my_caller(func_name, osintneting, fl):

    if ida_kernwin.user_cancelled():

        print('Cancelled')
        fl.close()
        exit()

    str = '{0}\t'.format(func_name)
    r_call_chain.append(str)
    addr = get_name_ea(0, func_name)
    addr_ref_to = get_first_fcref_to(addr)

    # 嵌套结束条件 

    osinteneting_end = False

    if addr_ref_to == BADADDR:
        osinteneting_end = True

    elif osintneting == -1:
        osinteneting_end = False

    elif osintneting == 1:
        osinteneting_end = True

    if osinteneting_end is True:

        length = len(r_call_chain)

        for idx in range(length):

            fl.write(r_call_chain[length - idx - 1])
            sys.stdout.write(r_call_chain[length - idx - 1])

        fl.write("\n")
        sys.stdout.write('\r\n')
        r_call_chain.pop()
        return

    # 深度优先

    while (addr_ref_to != BADADDR) and (addr_ref_to != addr):

        parent_func_name = get_func_name(addr_ref_to)
        get_my_caller(parent_func_name, osintneting - 1, fl)
        addr_ref_to = get_next_fcref_to(addr, addr_ref_to)

        if addr_ref_to == BADADDR:
            r_call_chain.pop() # 如果没有引用函数，弹出当前函数

            break
```