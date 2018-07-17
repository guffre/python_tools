from PIL import Image
import os
import random

def getpixel(img):
    # Generator to yield all coordinate pairs in a loaded Image
    for y in range(img.height):
        for x in range(img.width):
            yield (x,y)

def steg_size_check(img, length):
    # Checks the size an image is capable of hiding and returns 0 if data is too big
    max_size = (img.height*img.width*3*2)-30
    # (pixel_count*bands*bits_per_band)-bits_of_nondata
    if length >= 2**30:
        print("Data file exceeds max size capable of being stego'd")
        return 0
    if length*8 > max_size:
        print("Data file exceeds destination files capability: {} bytes".format(max_size/8))
        return 0
    return 1

def steg(image, data_file, output_file):
    # Open the image and data files
    img  = Image.open(image)
    with open(data_file, "rb") as f:
        data = bytearray(f.read())
    
    # Check to make sure the data can fit in the image
    data_len = len(data)
    if not steg_size_check(img,data_len):
        exit(1)
    
    bin_datalen = "{0:030b}".format(data_len)[::-1]
    length = len(bin_datalen) + data_len*8
    # Create a bit-generator of all the bits that will be stored in the image
    data = (int(n) for n in bin_datalen+''.join(map("{0:08b}".format, data)))
    
    # Setup random seed. This is used to obfuscate the binary data
    random.seed(data_len)
    pixels     = getpixel(img)
    checkpoint = length - 30
    randomizer = 0
    
    # Primary loop. Write all the bits, 2 bits into each RGB value of each pixel
    # So R <- 2 bits, G <- 2 bits, B <- 2 bits. Ignore any other channels/bands
    while length > 0:
        coord = pixels.next()
        pixel = list(img.getpixel(coord))
        # Checkpoint because we cannot randomize the length.
        if length <= checkpoint:
            randomizer = 1
        # Push our bits into the RGB values of current pixel
        for i,byte in enumerate(pixel[:3]):
            length -= 2
            try:
                # "Random" xors to obfuscate the data
                pixel[i] ^= random.randint(0,randomizer) #  0|1
                pixel[i] ^= random.randint(0,randomizer+randomizer) # 0|2
                dat = data.next()
                # Odd bytes are binary "1", even are "0"
                if byte&0b01 != dat:
                    pixel[i] ^= 0b01
                dat = data.next()
                if (byte&0b10)>>1 != dat:
                    pixel[i] ^= 0b10
            except StopIteration:
                break
            if length <= 0:
                break
        img.putpixel(coord,tuple(pixel))
    
    print("Saving file...")
    while os.path.isfile(output_file):
        c = raw_input("{} exists!\nOverwrite? [y/n] ".format(output_file))
        if c.lower() == "y":
            break
        else:
            output_file = raw_input("Enter new file path:\n> ")
    img.save(output_file)
    print("File saved at: {}".format(output_file))

def desteg(image, savefile):
    # Open image
    img = Image.open(image)
    pixels = getpixel(img)
    output = []
    out = 0
    # Get length of stego'd data
    for n in range(5):
        coord = pixels.next()
        print(coord)
        pixel = list(img.getpixel(coord))
        for i,byte in enumerate(pixel[:3]):
            output.append(byte&0b01)
            output.append((byte&0b10)>>1)
    
    # Translate backwards binary list into a number
    length = (reduce(lambda x,y: x << 1 | y, output[::-1]))*8
    output = []
    # Set the random seed for deobfuscating data
    random.seed(length/8)
    # This is the "checkpoint", there was no obfuscation of the 30 bits of the length
    for n in range(30):
        random.randint(0,0)
    # Loop through the file and pull the stego'd bits out
    while length > 0:
        coord = pixels.next()
        pixel = list(img.getpixel(coord))
        for i,byte in enumerate(pixel[:3]):
            byte ^= random.randint(0,1)
            byte ^= random.randint(0,2)
            output.append(byte&0b01)
            output.append((byte&0b10)>>1)
            length -= 2
            if length <= 0: 
                break
    
    # Turn the binary output into bytes in a bytearray
    data = bytearray()
    for i,n in enumerate(output[::8]):
        data.append(reduce(lambda x,y: x << 1 | y, output[i*8:i*8+8]))
    
    with open(savefile, "wb") as f:
        f.write(data)