from PIL import Image
import glob
import os
import sys
import argparse

def debug_print(*args, **kwargs):
    if kwargs['flush']: # Little trick, this is `if debug`
        print(*args, **kwargs)

def move_file(src, dst):
    _,file = os.path.split(src)
    file = os.path.join(dst,file)
    try:
        os.rename(src, file)
        print(f"[+] {src} -> {file}")
    except:
        print(f"[!] Error moving {src} to {file}")

def get_darkness(image,darker=0):
    """Gets a darkness value for the image by measuring the ratio of *bright*
    pixels to the size of the image. Lower bright count == darker image"""
    if darker > 127: darker = 127
    if darker < -127: darker = -127
    h = image.histogram()
    bR = h[128-darker:256]
    bG = h[384-darker:512]
    bB = h[640-darker:]

    # Divide by 2 since we are checking half the histogram (bright values only)
    pix = float(image.size[0]*image.size[1]/2)

    # Turn it into a percentage. Pure black = 100.0, pure white = 0.0
    dark = (1 - (sum(bR+bG+bB)/pix/2/3))*100
    return dark

def cropgen(img):
    """Generates a series of crops of the original image. These are located
    in each of the corners, and then two crops of the center. One horizontal, 
    one vertical to detect bright centers in otherwise dark images"""
    width, height = img.size
    hcrop = int(height*0.25)
    wcrop = int(width*0.25)
    crops = {"topleft":     (0,0,width-wcrop*2,height-hcrop*2),
             "topright":    (wcrop*2,0,width,height-hcrop),
             "center":      (wcrop,hcrop,width-wcrop,height-hcrop),
             "centervert":  (width*0.375,height*0.125,width-(width*0.375),height-(height*0.125)),
             "bottomleft":  (0, hcrop*2, width-wcrop*2, height),
             "bottomright": (wcrop*2,hcrop*2, width, height)}
    for crop in crops.values():
        yield img.crop(crop)
    yield img

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process images with specified darkness level.", allow_abbrev=False)
    parser.add_argument('-s', '--source',type=str, required=True, help="Source directory of images or individual source image")
    parser.add_argument('-d', '--dest',  type=str, required='--commit' in sys.argv, default="c:\\", help="Destination directory for dark images")
    parser.add_argument('-D', '--darkness', default=82, type=float, required=False, help="Darkness percentage (float between 0 and 100). 100 is black, 0 is white")
    parser.add_argument('-a', '--dark_adjust', default=0, type=int, required=False, help="Adjust what pixel values you consider to be dark. (int between -127 and 127). Higher value makes more pixels considered light, resulting in lower percentage of darkness. Negative values are opposite.")
    parser.add_argument('--commit', action='store_false', help="Commit changes (meaning actually move files). Default is to show debug output.")
    args = parser.parse_args()
    
    debug = args.commit
    
    if not (0 <= args.darkness <= 100):
        raise ValueError("Darkness value must be between 0 and 100 inclusive.")
    if not os.path.exists(args.source):
        raise ValueError(f"Source '{args.source}' does not exist")
    if not os.path.exists(args.dest) or not os.path.isdir(args.dest):
        raise ValueError(f"Destination directory '{args.dest}' does not exist or is not a directory.")
    if os.path.isdir(args.source) and os.path.split(args.source)[-1] != '*':
        args.source = os.path.join(args.source, '*')
    print(f"Moving files from {args.source} to {args.dest}\nDarkness modifier: {args.darkness}")
    for image_path in glob.glob(args.source):
        try:
            img = Image.open(image_path).convert("RGB")
        except:
            print(f"[!] Error opening file: {image_path}")
            continue
        for image in cropgen(img):
            dark = get_darkness(image,args.dark_adjust)
            debug_print(f"{dark=}\t| dark_adjust={args.dark_adjust}\t| {image_path}", flush=debug)
            if dark < args.darkness:
                debug_print(f"[*] {image_path} FAILED.", flush=debug)
                break
        else:
            if not debug:
                move_file(image_path, dst)
        img.close()
