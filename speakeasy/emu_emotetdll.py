import argparse
import speakeasy
import logging

#
# If you see an error in "CryptStringToBinary"
# you can skip it by modifying
#   "speakeasy/winenv/api/usermode/crypt32.py" as follow:
#
#         # s = self.read_mem_string(pszString, cw)  <-- Comment this
#         s = 'PLACEHOLDER'                          <-- Add this
#
# Also you may need to increase execution timeout
#

mstate = 0

def get_logger():
    """
    Get the default logger for speakeasy
    """
    logger = logging.getLogger('emu_dll')
    if not logger.handlers:
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.INFO)

    return logger


def hook_code(emu, begin, end, ctx):
    global mstate

    logger = get_logger()

    mnem, op, instr = emu.get_disasm(emu.reg_read('eip'),end)
    # print('%s: %s' % (hex(begin),instr))

    #
    # Control program state
    #
    if begin == 0x1000a7cc:
        # Print the new state at the beginning of each loop
        msg = '[+] State: %x' % (emu.reg_read('ecx'))
        logger.log(logging.INFO, msg)

        # If required, redirects to a different state
        if mstate and emu.reg_read('ecx') == 0x116d33a8:
            emu.reg_write('ecx',int(mstate,16))
            msg = '[+] Redirected to %x' % (int(mstate,16))
            logger.log(logging.INFO, msg)

    #
    # Skip invali calls (eax==0)
    #
    if instr == 'call eax' and emu.reg_read('eax') == 0:
        emu.reg_write('eip', begin + 2)
        msg = '[!] Skipped invalid call'
        logger.log(logging.INFO, msg)
    
    #
    # Print decrypted strings
    #
    if begin == 0x10006bf7 or begin == 0x10003537:
        # We are at the exit of the decrypt functions:
        # we have the pointer to the string (EBX) and
        # the length (EAX)
        strlen = emu.reg_read('eax')
        strptr = emu.reg_read('ebx')
        data = emu.mem_read(strptr, strlen*2)        
        msg = '[+] Decrypted string: %s' % (data.decode('utf-16'))
        logger.log(logging.INFO, msg)

    return 

def main(args):

    se = speakeasy.Speakeasy(logger=get_logger())
    module = se.load_module(args.file)

    se.run_module(module, all_entrypoints=False)
    se.add_code_hook(hook_code)

    # Set up some fake args
    arg0 = 1
    arg1 = 2
    # Start the RunDLL export
    for exp in module.get_exports():
        if exp.name == 'RunDLL':
            se.call(exp.address, [arg0, arg1])

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Emulate EMOTET DLL')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of DLL to emulate')
    parser.add_argument('-s', '--state', action='store', dest='mstate',
                        required=False, help='Redirect emulation to given state')
    args = parser.parse_args()
    mstate = args.mstate
    main(args)
