"""
generate_pwa_icons.py
Generates premium black & orange PWA icons for LR Popcorn Owner Portal.
Produces 512x512 and 192x192 standard and maskable Android icons.
"""
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import math
import os

def create_lr_owner_icon(size=1024, is_maskable=False):
    # Render at 1024x1024 for pristine antialiasing, downscale later
    img = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 1. Background
    # Maskable icons must fill the entire canvas (full-bleed square) so Android OS can mask it into any shape (circle, squircle, round-rect).
    # Standard icons have smooth rounded corners.
    bg_color = (12, 13, 15, 255) # #0c0d0f deep luxury charcoal/black
    if is_maskable:
        draw.rectangle([0, 0, 1024, 1024], fill=bg_color)
    else:
        # Rounded rectangle
        corner_radius = 210
        draw.rounded_rectangle([0, 0, 1024, 1024], radius=corner_radius, fill=bg_color)

    # 2. Subtle radial glow behind the center emblem
    glow_layer = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow_layer)
    cx, cy = 512, 490
    for r in range(360, 20, -15):
        alpha = int(45 * (1 - r / 360))
        glow_draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 107, 36, alpha))
    glow_layer = glow_layer.filter(ImageFilter.GaussianBlur(25))
    img = Image.alpha_composite(img, glow_layer)
    draw = ImageDraw.Draw(img)

    # 3. Subtle fine border ring (inside icon)
    border_inset = 40 if not is_maskable else 80
    border_rad = 180 if not is_maskable else 120
    draw.rounded_rectangle(
        [border_inset, border_inset, 1024 - border_inset, 1024 - border_inset],
        radius=border_rad,
        outline=(255, 110, 38, 70),
        width=6
    )

    # Safe margin scaling for maskable icons (must keep elements inside center 70% safe circle)
    scale = 0.78 if is_maskable else 0.94
    offset_y = 10 if is_maskable else 0

    # 4. Draw sparkling 4-pointed star emblem at top center
    star_cy = int(240 * scale) + offset_y + (60 if is_maskable else 0)
    star_cx = 512
    star_h = int(105 * scale)
    star_w = int(75 * scale)
    star_points = [
        (star_cx, star_cy - star_h), # Top
        (star_cx + int(star_w * 0.28), star_cy - int(star_h * 0.28)),
        (star_cx + star_w, star_cy), # Right
        (star_cx + int(star_w * 0.28), star_cy + int(star_h * 0.28)),
        (star_cx, star_cy + star_h), # Bottom
        (star_cx - int(star_w * 0.28), star_cy + int(star_h * 0.28)),
        (star_cx - star_w, star_cy), # Left
        (star_cx - int(star_w * 0.28), star_cy - int(star_h * 0.28)),
    ]
    # Star glow
    star_layer = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    star_draw = ImageDraw.Draw(star_layer)
    star_draw.polygon(star_points, fill=(255, 120, 45, 255))
    blurred_star = star_layer.filter(ImageFilter.GaussianBlur(16))
    img = Image.alpha_composite(img, blurred_star)
    draw = ImageDraw.Draw(img)
    draw.polygon(star_points, fill=(255, 125, 45, 255))

    # Inner bright star core
    core_h = int(star_h * 0.55)
    core_w = int(star_w * 0.55)
    core_points = [
        (star_cx, star_cy - core_h),
        (star_cx + int(core_w * 0.28), star_cy - int(core_h * 0.28)),
        (star_cx + core_w, star_cy),
        (star_cx + int(core_w * 0.28), star_cy + int(core_h * 0.28)),
        (star_cx, star_cy + core_h),
        (star_cx - int(core_w * 0.28), star_cy + int(core_h * 0.28)),
        (star_cx - core_w, star_cy),
        (star_cx - int(core_w * 0.28), star_cy - int(core_h * 0.28)),
    ]
    draw.polygon(core_points, fill=(255, 240, 220, 255))

    # 5. Bold Typography "LR"
    font_path = "C:/Windows/Fonts/seguiemb.ttf" # Segoe UI Bold / Semibold
    if not os.path.exists(font_path):
        font_path = "C:/Windows/Fonts/arialbd.ttf"
    
    lr_font_size = int(320 * scale)
    lr_font = ImageFont.truetype(font_path, lr_font_size)
    
    lr_text = "LR"
    bbox = lr_font.getbbox(lr_text)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    
    lr_x = 512 - text_w // 2 - bbox[0]
    lr_y = int(500 * scale) - text_h // 2 + offset_y + (40 if is_maskable else 0)

    # Orange Drop Shadow for "LR"
    lr_shadow_layer = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    lr_shadow_draw = ImageDraw.Draw(lr_shadow_layer)
    lr_shadow_draw.text((lr_x, lr_y + 12), lr_text, font=lr_font, fill=(255, 107, 36, 180))
    lr_shadow_layer = lr_shadow_layer.filter(ImageFilter.GaussianBlur(18))
    img = Image.alpha_composite(img, lr_shadow_layer)
    draw = ImageDraw.Draw(img)

    # Crisp white text "LR"
    draw.text((lr_x, lr_y), lr_text, font=lr_font, fill=(255, 255, 255, 255))

    # 6. "OWNER" Pill Badge
    badge_w = int(440 * scale)
    badge_h = int(108 * scale)
    badge_x1 = 512 - badge_w // 2
    badge_y1 = int(725 * scale) + offset_y + (30 if is_maskable else 0)
    badge_x2 = badge_x1 + badge_w
    badge_y2 = badge_y1 + badge_h
    badge_rad = badge_h // 2

    # Badge glow
    badge_glow_layer = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    badge_glow_draw = ImageDraw.Draw(badge_glow_layer)
    badge_glow_draw.rounded_rectangle([badge_x1, badge_y1, badge_x2, badge_y2], radius=badge_rad, fill=(255, 107, 36, 170))
    badge_glow_layer = badge_glow_layer.filter(ImageFilter.GaussianBlur(14))
    img = Image.alpha_composite(img, badge_glow_layer)
    draw = ImageDraw.Draw(img)

    # Gradient Badge Surface: draw gradient lines inside rounded rectangle
    badge_mask = Image.new("L", (1024, 1024), 0)
    badge_mask_draw = ImageDraw.Draw(badge_mask)
    badge_mask_draw.rounded_rectangle([badge_x1, badge_y1, badge_x2, badge_y2], radius=badge_rad, fill=255)

    badge_surface = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    bs_draw = ImageDraw.Draw(badge_surface)
    for y in range(badge_y1, badge_y2 + 1):
        ratio = (y - badge_y1) / max(1, badge_h)
        r = int(255 * (1 - ratio) + 215 * ratio)
        g = int(120 * (1 - ratio) + 70 * ratio)
        b = int(45 * (1 - ratio) + 20 * ratio)
        bs_draw.line([(badge_x1, y), (badge_x2, y)], fill=(r, g, b, 255))
    
    img.paste(badge_surface, (0, 0), badge_mask)
    draw = ImageDraw.Draw(img)

    # Badge Text "OWNER"
    badge_font_size = int(52 * scale)
    badge_font = ImageFont.truetype(font_path, badge_font_size)
    badge_text = "O W N E R"
    b_bbox = badge_font.getbbox(badge_text)
    b_w = b_bbox[2] - b_bbox[0]
    b_h = b_bbox[3] - b_bbox[1]
    b_x = 512 - b_w // 2 - b_bbox[0]
    b_y = badge_y1 + (badge_h - b_h) // 2 - b_bbox[1] - 2

    # Badge text shadow and text
    draw.text((b_x, b_y + 2), badge_text, font=badge_font, fill=(160, 45, 10, 200))
    draw.text((b_x, b_y), badge_text, font=badge_font, fill=(255, 255, 255, 255))

    return img

def main():
    print("Generating LR Owner PWA icons...")
    # Standard 1024 master
    master_std = create_lr_owner_icon(1024, is_maskable=False)
    # Maskable 1024 master (with safe-zone margins)
    master_maskable = create_lr_owner_icon(1024, is_maskable=True)

    # Resize to 512x512 and 192x192 with Lanczos resampling
    icon_512 = master_std.resize((512, 512), Image.Resampling.LANCZOS)
    icon_192 = master_std.resize((192, 192), Image.Resampling.LANCZOS)
    maskable_512 = master_maskable.resize((512, 512), Image.Resampling.LANCZOS)
    maskable_192 = master_maskable.resize((192, 192), Image.Resampling.LANCZOS)

    icon_512.save("owner-icon-512.png", "PNG", optimize=True)
    icon_192.save("owner-icon-192.png", "PNG", optimize=True)
    maskable_512.save("owner-icon-maskable-512.png", "PNG", optimize=True)
    maskable_192.save("owner-icon-maskable-192.png", "PNG", optimize=True)
    
    print("Saved owner-icon-512.png, owner-icon-192.png, owner-icon-maskable-512.png, owner-icon-maskable-192.png successfully!")

if __name__ == "__main__":
    main()
