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