# stegopng.py

Python stegonography tool with builtin encryption/obfuscation of the data.
Places 6 bits of data into each pixel of a .png-type file.
Only tested with .png files, but will probably work with .bmp files as well.

Oh, it also encrypts the data. Nice.

## Usage

    There is no "main", you will need to import the code into your project.
    
        def steg(image, data_file, output_file)
        
    You can call it like: `steg("C:\\my_picture.png", "E:\\some_document.pdf", "C:\\my_picture_stego.png")`
    
    `desteg()` works in a similar fashion: `def desteg(image, savefile):`
    
    