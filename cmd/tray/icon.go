package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

var (
	iconConnected    []byte
	iconDisconnected []byte
)

func init() {
	iconConnected = generateTrayIcon(true)
	iconDisconnected = generateTrayIcon(false)
}

func generateTrayIcon(connected bool) []byte {
	const size = 22
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	black := color.NRGBA{R: 0, G: 0, B: 0, A: 255}
	cx := float64(size) / 2

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5

			if connected {
				dx, dy := fx-cx, fy-cx
				if dx*dx+dy*dy <= 10.0*10.0 {
					img.Set(x, y, black)
				}
				if isDollarSign(fx, fy, cx, cx, 6.0) {
					img.Set(x, y, color.NRGBA{})
				}
			} else {
				dx, dy := fx-cx, fy-cx
				dist := math.Sqrt(dx*dx + dy*dy)
				if dist <= 10.0 && dist >= 8.5 {
					img.Set(x, y, black)
				}
				if isDollarSign(fx, fy, cx, cx, 6.0) {
					img.Set(x, y, black)
				}
			}
		}
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func isDollarSign(x, y, cx, cy, scale float64) bool {
	barHalfW := scale * 0.12
	barTop := cy - scale*0.95
	barBot := cy + scale*0.95
	if math.Abs(x-cx) <= barHalfW && y >= barTop && y <= barBot {
		return true
	}

	nx := (x - cx) / scale
	ny := (y - cy) / scale
	thickness := 0.18

	topCy := -0.32
	topR := 0.38
	tdx, tdy := nx, ny-topCy
	topDist := math.Sqrt(tdx*tdx + tdy*tdy)
	if topDist >= topR-thickness && topDist <= topR+thickness {
		angle := math.Atan2(tdy, tdx)
		if angle >= -math.Pi && angle <= math.Pi*0.55 {
			return true
		}
	}

	botCy := 0.32
	botR := 0.38
	bdx, bdy := nx, ny-botCy
	botDist := math.Sqrt(bdx*bdx + bdy*bdy)
	if botDist >= botR-thickness && botDist <= botR+thickness {
		angle := math.Atan2(bdy, bdx)
		if angle >= -math.Pi*0.55 && angle <= math.Pi {
			return true
		}
	}

	return false
}
