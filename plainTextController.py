from utils import IP, E_BIT_SELECTION, S_BOXES, P, IP_1


def binaryBlockSpliter(binary):
    midpoint = len(binary) // 2
    left = binary[:midpoint]
    right = binary[midpoint:]
    return left, right


def paddedStringBlocks(plainText):
    binary = ''.join(format(ord(char), '08b') for char in plainText)
    binary = binary.zfill((len(binary) + 63) // 64 * 64)
    blocks = [binary[i:i+64] for i in range(0, len(binary), 64)]
    plainTextBinaryBlocks = blocks
    return blocks


def IPBlockMapping(binary):
    if len(binary) != 64:
        raise ValueError("Block must be 64 bits long")

    result = ''.join(binary[i - 1] for i in IP)
    return result


def EBitSelectionMapping(binary):
    if len(binary) != 32:
        raise ValueError("Block must be 32 bits long")

    result = ''.join(binary[i - 1] for i in E_BIT_SELECTION)
    return result

def XOR(bin1, bin2):
    if len(bin1) != len(bin2):
        raise ValueError("Length of the binary strings must be the same")
    length = max(len(bin1), len(bin2))
    result = ''.join('1' if bit1 != bit2 else '0' for bit1, bit2 in zip(bin1, bin2))
    return result

def SBoxSubsitution(binary):
    if len(binary) != 48:
        raise ValueError(f"Input must be a 48-bit binary string. Got {len(binary)} bits.")

    blocks = [binary[i:i+6] for i in range(0, 48, 6)]
    output = []

    for i in range(8):
        block = blocks[i]
        row = int(block[0] + block[5], 2)
        column = int(block[1:5], 2)
        value = S_BOXES[i][row][column]
        output.append(f"{value:04b}")
    result = ''.join(output)
    # print(f"S-box input: {binary}")
    # print(f"S-box output: {result}")
    
    
    if len(result) != 32:
        print(f"Error: Result after S-box substitution has incorrect length. Got {len(result)} bits.")
        raise ValueError(f"Output after S-box substitution is not 32 bits. Got {len(result)} bits.")

    return result


def PBlockMapping(binary):
    if len(binary) != 32:
        raise ValueError("Block must be 32 bits long")

    result = ''.join(binary[i - 1] for i in P)
    return result

def IP_1BlockMapping(binary):
    if len(binary) != 64:
        raise ValueError("Block must be 32 bits long")

    result = ''.join(binary[i - 1] for i in IP_1)
    return result
