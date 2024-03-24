def decrypt(encrypted, key):
    offset = 0
    senc_boxes = deque()
    trun_boxes = deque()
    box = Box.parse(encrypted)

    while box.type != b'moof':
        offset += box.end
        box = Box.parse(encrypted[offset:])

    if box.type == b'moof':
        senc_boxes.extend(BoxUtil.find(box, b'senc'))
        trun_boxes.extend(BoxUtil.find(box, b'trun'))
    
    mdat = offset + box.end
    box = Box.parse(encrypted[mdat:])

    if box.type == b'mdat':
        senc_box = senc_boxes.popleft()
        trun_box = trun_boxes.popleft()

        clear_box = b''
        with BytesIO(box.data) as box_bytes:
            for sample, sample_info in zip(senc_box.sample_encryption_info, trun_box.sample_info):
                counter = Counter.new(64, prefix=sample.iv, initial_value=0)
                cipher = AES.new(binascii.unhexlify(key), AES.MODE_CTR, counter=counter)
                if not sample.subsample_encryption_info:
                    cipher_bytes = box_bytes.read(sample_info.sample_size)
                    clear_box += cipher.decrypt(cipher_bytes)
                else:
                    for subsample in sample.subsample_encryption_info:
                        clear_box += box_bytes.read(subsample.clear_bytes)
                        cipher_bytes = box_bytes.read(subsample.cipher_bytes)
                        clear_box += cipher.decrypt(cipher_bytes) 
        box.data = clear_box

  return encrypted[:mdat] + Box.build(box)
