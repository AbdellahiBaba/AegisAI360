package main

func generateICO(r, g, b byte) []byte {
	width := 16
	height := 16

	bmpDataSize := width * height * 4
	andMaskRowBytes := ((width + 31) / 32) * 4
	andMaskSize := andMaskRowBytes * height
	bmpHeaderSize := 40
	icoHeaderSize := 6
	icoDirSize := 16
	imageDataSize := bmpHeaderSize + bmpDataSize + andMaskSize
	totalSize := icoHeaderSize + icoDirSize + imageDataSize

	ico := make([]byte, totalSize)

	ico[0] = 0
	ico[1] = 0
	ico[2] = 1
	ico[3] = 0
	ico[4] = 1
	ico[5] = 0

	offset := 6
	ico[offset+0] = byte(width)
	ico[offset+1] = byte(height)
	ico[offset+2] = 0
	ico[offset+3] = 0
	ico[offset+4] = 1
	ico[offset+5] = 0
	ico[offset+6] = 32
	ico[offset+7] = 0
	putU32LE(ico, offset+8, uint32(imageDataSize))
	imgOffset := uint32(icoHeaderSize + icoDirSize)
	putU32LE(ico, offset+12, imgOffset)

	bmp := ico[imgOffset:]
	putU32LE(bmp, 0, uint32(bmpHeaderSize))
	putU32LE(bmp, 4, uint32(width))
	putU32LE(bmp, 8, uint32(height*2))
	bmp[12] = 1
	bmp[13] = 0
	bmp[14] = 32
	bmp[15] = 0
	putU32LE(bmp, 20, uint32(bmpDataSize+andMaskSize))

	pixels := bmp[bmpHeaderSize:]
	andMask := bmp[bmpHeaderSize+bmpDataSize:]

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			idx := (y*width + x) * 4
			cx := float64(x) - 7.5
			cy := float64(y) - 7.5
			dist := cx*cx + cy*cy

			isTransparent := true

			if dist < 49 {
				pixels[idx+0] = b
				pixels[idx+1] = g
				pixels[idx+2] = r
				pixels[idx+3] = 255
				isTransparent = false
			}

			if dist >= 49 && dist < 56 {
				pixels[idx+0] = b / 2
				pixels[idx+1] = g / 2
				pixels[idx+2] = r / 2
				pixels[idx+3] = 200
				isTransparent = false
			}

			if dist < 20 {
				pixels[idx+0] = 40
				pixels[idx+1] = 40
				pixels[idx+2] = 50
				pixels[idx+3] = 255
			}

			if dist < 4 {
				pixels[idx+0] = 60
				pixels[idx+1] = 180
				pixels[idx+2] = 220
				pixels[idx+3] = 255
			}

			if isTransparent {
				pixels[idx+0] = 0
				pixels[idx+1] = 0
				pixels[idx+2] = 0
				pixels[idx+3] = 0
				byteIdx := y*andMaskRowBytes + x/8
				bitIdx := uint(7 - x%8)
				andMask[byteIdx] |= 1 << bitIdx
			}
		}
	}

	return ico
}

func putU32LE(b []byte, offset int, v uint32) {
	b[offset] = byte(v)
	b[offset+1] = byte(v >> 8)
	b[offset+2] = byte(v >> 16)
	b[offset+3] = byte(v >> 24)
}

var iconConnected = generateICO(50, 200, 80)
var iconDisconnected = generateICO(220, 60, 60)
