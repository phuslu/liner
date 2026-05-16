//go:build ignore

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

type icnsIcon struct {
	code string
	data []byte
}

func main() {
	output := "Liner.icns"
	if len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: go run liner-ico.go [output.icns]")
		os.Exit(2)
	}
	if len(os.Args) == 2 {
		output = os.Args[1]
	}

	types := map[int]string{
		16:   "icp4",
		32:   "icp5",
		64:   "icp6",
		128:  "ic07",
		256:  "ic08",
		512:  "ic09",
		1024: "ic10",
	}

	var icons []icnsIcon
	for _, size := range []int{16, 32, 64, 128, 256, 512, 1024} {
		var b bytes.Buffer
		if err := png.Encode(&b, renderIcon(size)); err != nil {
			fmt.Fprintf(os.Stderr, "encode %dpx icon: %v\n", size, err)
			os.Exit(1)
		}
		icons = append(icons, icnsIcon{code: types[size], data: b.Bytes()})
	}
	if err := writeICNS(output, icons); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeICNS(path string, icons []icnsIcon) error {
	var total uint32 = 8
	for _, icon := range icons {
		total += uint32(8 + len(icon.data))
	}

	var b bytes.Buffer
	b.WriteString("icns")
	if err := binary.Write(&b, binary.BigEndian, total); err != nil {
		return err
	}
	for _, icon := range icons {
		b.WriteString(icon.code)
		if err := binary.Write(&b, binary.BigEndian, uint32(8+len(icon.data))); err != nil {
			return err
		}
		b.Write(icon.data)
	}
	return os.WriteFile(path, b.Bytes(), 0644)
}

func renderIcon(size int) image.Image {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	radius := s * 0.225

	for y := range size {
		for x := range size {
			px, py := float64(x)+0.5, float64(y)+0.5
			mask := roundedRectAlpha(px, py, s, s, radius)
			if mask == 0 {
				continue
			}

			t := py / s
			r := mix(17, 11, t)
			g := mix(126, 31, t)
			b := mix(189, 73, t)
			glow := math.Max(0, 1-math.Hypot((px-s*0.32)/(s*0.62), (py-s*0.22)/(s*0.52)))
			r += glow * 38
			g += glow * 58
			b += glow * 38

			img.SetNRGBA(x, y, over(img.NRGBAAt(x, y), r, g, b, mask))

			top := clamp(1-py/(s*0.42), 0, 1) * 0.22 * mask
			img.SetNRGBA(x, y, over(img.NRGBAAt(x, y), 255, 255, 255, top))

			edge := 1 - roundedRectAlpha(px, py, s-2, s-2, radius-1)
			img.SetNRGBA(x, y, over(img.NRGBAAt(x, y), 255, 255, 255, clamp(edge, 0, 1)*0.20*mask))
		}
	}

	drawGlyph(img, size, 0, s*0.024, 0, 0, 0, 0.24)
	drawGlyph(img, size, 0, 0, 255, 255, 255, 0.95)
	return img
}

func drawGlyph(img *image.NRGBA, size int, ox, oy, r, g, b, alpha float64) {
	s := float64(size)
	points := [][2]float64{
		{s*0.30 + ox, s*0.36 + oy},
		{s*0.49 + ox, s*0.36 + oy},
		{s*0.70 + ox, s*0.50 + oy},
		{s*0.49 + ox, s*0.64 + oy},
		{s*0.30 + ox, s*0.64 + oy},
	}
	lineWidth := math.Max(1.6, s*0.070)
	nodeRadius := math.Max(2.4, s*0.084)

	for y := range size {
		for x := range size {
			px, py := float64(x)+0.5, float64(y)+0.5
			a := 0.0
			for _, segment := range [][2]int{{0, 1}, {1, 2}, {4, 3}, {3, 2}} {
				d := distanceToSegment(px, py, points[segment[0]][0], points[segment[0]][1], points[segment[1]][0], points[segment[1]][1])
				a = math.Max(a, clamp(lineWidth/2+0.9-d, 0, 1))
			}
			for _, p := range [][2]float64{points[0], points[2], points[4]} {
				d := math.Hypot(px-p[0], py-p[1])
				a = math.Max(a, clamp(nodeRadius+0.9-d, 0, 1))
			}
			if a > 0 {
				img.SetNRGBA(x, y, over(img.NRGBAAt(x, y), r, g, b, a*alpha))
			}
		}
	}
}

func roundedRectAlpha(x, y, w, h, r float64) float64 {
	qx := math.Abs(x-w/2) - w/2 + r
	qy := math.Abs(y-h/2) - h/2 + r
	outside := math.Hypot(math.Max(qx, 0), math.Max(qy, 0))
	inside := math.Min(math.Max(qx, qy), 0)
	return clamp(0.5-(outside+inside-r), 0, 1)
}

func distanceToSegment(px, py, ax, ay, bx, by float64) float64 {
	vx, vy := bx-ax, by-ay
	wx, wy := px-ax, py-ay
	t := clamp((wx*vx+wy*vy)/(vx*vx+vy*vy), 0, 1)
	return math.Hypot(px-(ax+t*vx), py-(ay+t*vy))
}

func over(dst color.NRGBA, r, g, b, a float64) color.NRGBA {
	sa := clamp(a, 0, 1)
	da := float64(dst.A) / 255
	oa := sa + da*(1-sa)
	if oa == 0 {
		return color.NRGBA{}
	}

	dr := float64(dst.R) / 255
	dg := float64(dst.G) / 255
	db := float64(dst.B) / 255
	or := (r/255*sa + dr*da*(1-sa)) / oa
	og := (g/255*sa + dg*da*(1-sa)) / oa
	ob := (b/255*sa + db*da*(1-sa)) / oa
	return color.NRGBA{
		R: byte(clamp(or, 0, 1)*255 + 0.5),
		G: byte(clamp(og, 0, 1)*255 + 0.5),
		B: byte(clamp(ob, 0, 1)*255 + 0.5),
		A: byte(oa*255 + 0.5),
	}
}

func mix(a, b, t float64) float64 {
	return a + (b-a)*t
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
