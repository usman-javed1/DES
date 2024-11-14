import base64

# Permutation and substitution tables
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

E_BIT_SELECTION = [32, 1, 2, 3, 4, 5, 4, 5,
                   6, 7, 8, 9, 8, 9, 10, 11,
                   12, 13, 12, 13, 14, 15, 16, 17,
                   16, 17, 18, 19, 20, 21, 20, 21,
                   22, 23, 24, 25, 24, 25, 26, 27,
                   28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

IP_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

SHIFT_PATTERN = {
    1: 1, 2: 1, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 8: 2,
    9: 1, 10: 2, 11: 2, 12: 2, 13: 2, 14: 2, 15: 2, 16: 1
}
import base64

# Permutation and substitution tables (as provided)
# PC1, PC2, IP, IP_1, E_BIT_SELECTION, P, S_BOXES, SHIFT_PATTERN

# Function to convert text to binary
def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

# Function to apply a permutation
def apply_permutation(block, table):
    return ''.join(block[i - 1] for i in table)

# Function to split a binary block
def split_block(block):
    midpoint = len(block) // 2
    return block[:midpoint], block[midpoint:]

# Function to XOR two binary strings
def xor(bin1, bin2):
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bin1, bin2))

# Function to pad plaintext using PKCS7
def pkcs7_padding(text, block_size=8):
    pad_len = block_size - (len(text) % block_size)
    padding = chr(pad_len) * pad_len
    return text + padding

# DES encryption function for a single 8-byte block
def des_encrypt_block(plain_block, round_keys):
    binary_plaintext = text_to_binary(plain_block)
    permuted_text = apply_permutation(binary_plaintext[:64], IP)
    left, right = split_block(permuted_text)
    
    for round in range(16):
        expanded_right = apply_permutation(right, E_BIT_SELECTION)
        xor_result = xor(expanded_right, round_keys[round])
        
        substituted = ''.join(format(S_BOXES[i][int(block[0] + block[-1], 2)][int(block[1:5], 2)], '04b')
                            for i, block in enumerate([xor_result[i:i+6] for i in range(0, 48, 6)]))
        permuted_substitution = apply_permutation(substituted, P)
        
        new_right = xor(left, permuted_substitution)
        left, right = right, new_right
    
    # Final permutation
    final_permutation = apply_permutation(right + left, IP_1)
    return final_permutation

# DES encryption function for the entire text
def des_encrypt(plain_text, key):
    
    plain_text = pkcs7_padding(plain_text)
    
    binary_key = apply_permutation(text_to_binary(key), PC1)
    left_key, right_key = split_block(binary_key)
    
    
    round_keys = []
    for round in range(1, 17):
        shifts = SHIFT_PATTERN[round]
        left_key = left_key[shifts:] + left_key[:shifts]
        right_key = right_key[shifts:] + right_key[:shifts]
        combined_key = left_key + right_key
        round_keys.append(apply_permutation(combined_key, PC2))
    
    # Process each 8-byte block
    encrypted_blocks = []
    for i in range(0, len(plain_text), 8):
        block = plain_text[i:i + 8]
        encrypted_block = des_encrypt_block(block, round_keys)
        
        # Convert to bytes and then Base64 encode
        encrypted_bytes = int(encrypted_block, 2).to_bytes(8, byteorder='big')
        encrypted_blocks.append(encrypted_bytes)
    
    # Combine all encrypted blocks and encode to Base64
    encrypted_data = b''.join(encrypted_blocks)
    encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
    return encrypted_base64


def des_decrypt_block(encrypted_block, round_keys):
    binary_block = format(int.from_bytes(encrypted_block, byteorder='big'), '064b')
    permuted_text = apply_permutation(binary_block, IP)
    left, right = split_block(permuted_text)
    
    # 16 DES rounds (in reverse order for decryption)
    for round in reversed(range(16)):
        expanded_right = apply_permutation(right, E_BIT_SELECTION)
        xor_result = xor(expanded_right, round_keys[round])
        
        # S-Box substitution
        substituted = ''.join(format(S_BOXES[i][int(block[0] + block[-1], 2)][int(block[1:5], 2)], '04b')
                              for i, block in enumerate([xor_result[i:i+6] for i in range(0, 48, 6)]))
        permuted_substitution = apply_permutation(substituted, P)
        
        new_right = xor(left, permuted_substitution)
        left, right = right, new_right
    
    # Final permutation
    final_permutation = apply_permutation(right + left, IP_1)
    return final_permutation

# DES decryption function for the entire text
def des_decrypt(encrypted_base64, key):
    encrypted_data = base64.b64decode(encrypted_base64)
    
    binary_key = apply_permutation(text_to_binary(key), PC1)
    left_key, right_key = split_block(binary_key)
    
    # Generate round keys
    round_keys = []
    for round in range(1, 17):
        shifts = SHIFT_PATTERN[round]
        left_key = left_key[shifts:] + left_key[:shifts]
        right_key = right_key[shifts:] + right_key[:shifts]
        combined_key = left_key + right_key
        round_keys.append(apply_permutation(combined_key, PC2))
    
    # Process each 8-byte block
    decrypted_blocks = []
    for i in range(0, len(encrypted_data), 8):
        block = encrypted_data[i:i + 8]
        decrypted_block_binary = des_decrypt_block(block, round_keys)
        
        # Convert binary to text
        decrypted_block = ''.join(chr(int(decrypted_block_binary[i:i+8], 2)) for i in range(0, 64, 8))
        decrypted_blocks.append(decrypted_block)
    
    # Combine all decrypted blocks and remove padding
    decrypted_text = ''.join(decrypted_blocks)
    pad_len = ord(decrypted_text[-1])
    return decrypted_text[:-pad_len] if pad_len <= 8 else decrypted_text


    

# Example usage
if __name__ == "__main__":
    plaintext = "Information security covers the tools and processes that organizations use to protect information. This includes policy settings that prevent unauthorized people from accessing business or personal information. InfoSec is a growing and evolving field that covers a wide range of fields, from network and infrastructure security to testing and auditing.  Information security protects sensitive information from unauthorized activities, including inspection,modification, recording, and any disruption or destruction. The goal is to ensure the safety and privacy of critical data such as customer account detai ls, financial data or intellectual property.  The consequences of security incidents include theft of private information, data tampering, and data deletio n. Attacks can disrupt work processes and damage a company’s reputation, and also have a tangible cost.  Organizations must allocate funds for security and ensure that they are ready to detect, respond to, and proactively prevent, attacks such as phishing, malware, viruses, malicious insiders, and ransomware."
    key = "USMANJAV"
    encrypted_text = des_encrypt(plaintext, key)
    print("Encrypted (Base64):", encrypted_text)
    decrypted_text = des_decrypt(encrypted_text, key)
    print("Decrypted:", decrypted_text)
