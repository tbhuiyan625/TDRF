"""
Generate demo screenshots for TDRF documentation
"""
from PIL import Image, ImageDraw, ImageFont
import os

def create_banner():
    """Create project banner"""
    width, height = 1200, 300
    img = Image.new('RGB', (width, height), color='#1e3c72')
    draw = ImageDraw.Draw(img)
    
    try:
        # Try to use a nice font
        font_large = ImageFont.truetype("arial.ttf", 60)
        font_medium = ImageFont.truetype("arial.ttf", 30)
        font_small = ImageFont.truetype("arial.ttf", 20)
    except:
        # Fallback to default font
        font_large = ImageFont.load_default()
        font_medium = ImageFont.load_default()
        font_small = ImageFont.load_default()
    
    # Draw title
    text = "🔒 TDRF"
    bbox = draw.textbbox((0, 0), text, font=font_large)
    text_width = bbox[2] - bbox[0]
    draw.text(((width - text_width) / 2, 60), text, fill='white', font=font_large)
    
    # Draw subtitle
    text = "Threat Detection & Response Framework"
    bbox = draw.textbbox((0, 0), text, font=font_medium)
    text_width = bbox[2] - bbox[0]
    draw.text(((width - text_width) / 2, 140), text, fill='#a8b2d1', font=font_medium)
    
    # Draw tagline
    text = "Professional Security Analysis Tool for Cybersecurity Professionals"
    bbox = draw.textbbox((0, 0), text, font=font_small)
    text_width = bbox[2] - bbox[0]
    draw.text(((width - text_width) / 2, 200), text, fill='#667eea', font=font_small)
    
    os.makedirs('screenshots', exist_ok=True)
    img.save('screenshots/banner.png')
    print("✓ Created: screenshots/banner.png")

def create_cli_screenshot():
    """Create CLI interface screenshot"""
    width, height = 1000, 600
    img = Image.new('RGB', (width, height), color='#0c0c0c')
    draw = ImageDraw.Draw(img)
    
    try:
        font = ImageFont.truetype("consola.ttf", 14)
    except:
        font = ImageFont.load_default()
    
    cli_text = """
    ══════════════════════════════════════════════════════════════════
    ║  ████████╗██████╗ ██████╗ ███████╗                           ║
    ║  ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝                           ║
    ║     ██║   ██║  ██║██████╔╝█████╗                             ║
    ║     ██║   ██║  ██║██╔══██╗██╔══╝                             ║
    ║     ██║   ██████╔╝██║  ██║██║                                ║
    ╚═════════════════════════════════════════════════════════════════╝
    
    ┌──────────────────────────────────────────┐
    │          MAIN MENU                       │
    ├──────────────────────────────────────────┤
    │ [1] Log Analysis & Threat Detection      │
    │ [2] Network Port Scanning                │
    │ [3] Event Correlation Analysis           │
    │ [4] Generate Security Report             │
    │ [5] View Detection Dashboard             │
    │ [0] Exit                                 │
    └──────────────────────────────────────────┘
    
    ┌─[TDRF]─[~]
    └──╼ $ _
    """
    
    y_offset = 20
    for line in cli_text.split('\n'):
        draw.text((20, y_offset), line, fill='#00ff00', font=font)
        y_offset += 20
    
    img.save('screenshots/cli_interface.png')
    print("✓ Created: screenshots/cli_interface.png")

def create_port_scan_screenshot():
    """Create port scan results screenshot"""
    width, height = 1000, 500
    img = Image.new('RGB', (width, height), color='#0c0c0c')
    draw = ImageDraw.Draw(img)
    
    try:
        font = ImageFont.truetype("consola.ttf", 12)
    except:
        font = ImageFont.load_default()
    
    scan_text = """
    [*] Starting Quick Scan on 192.168.1.100
    [*] Scanning 20 most common ports...
    
    [+] Open: 22/tcp  - SSH-2.0-OpenSSH_8.2p1
    [+] Open: 80/tcp  - Apache httpd 2.4.41
    [+] Open: 443/tcp - nginx 1.18.0 (Ubuntu)
    [!] HIGH RISK: Port 445/tcp - Microsoft-DS (SMB)
    [+] Open: 3306/tcp - MySQL 5.7.33
    
    ══════════════════════════════════════════════════════════
      SCAN RESULTS
    ══════════════════════════════════════════════════════════
    
    Target: 192.168.1.100
    Ports Scanned: 20
    Duration: 2.34 seconds
    Open Ports: 5
    
    [!] HIGH RISK PORTS DETECTED:
        Port 445/tcp - SMB (Potential EternalBlue vulnerability)
    
    [✓] Scan complete! Check reports/ for detailed analysis.
    """
    
    y_offset = 20
    for line in scan_text.split('\n'):
        if 'HIGH RISK' in line or '[!]' in line:
            color = '#ff0000'
        elif '[+]' in line:
            color = '#00ff00'
        elif '[*]' in line:
            color = '#ffff00'
        else:
            color = '#ffffff'
        
        draw.text((20, y_offset), line, fill=color, font=font)
        y_offset += 18
    
    img.save('screenshots/port_scan.png')
    print("✓ Created: screenshots/port_scan.png")

def create_placeholder_images():
    """Create placeholder images for GUI and report"""
    # GUI Dashboard placeholder
    width, height = 1200, 800
    img = Image.new('RGB', (width, height), color='#f5f5f5')
    draw = ImageDraw.Draw(img)
    
    try:
        font_large = ImageFont.truetype("arial.ttf", 40)
        font_small = ImageFont.truetype("arial.ttf", 20)
    except:
        font_large = ImageFont.load_default()
        font_small = ImageFont.load_default()
    
    # Draw placeholder text
    text = "GUI Dashboard"
    bbox = draw.textbbox((0, 0), text, font=font_large)
    text_width = bbox[2] - bbox[0]
    draw.text(((width - text_width) / 2, height / 2 - 40), text, fill='#333333', font=font_large)
    
    text = "(Screenshot of running application)"
    bbox = draw.textbbox((0, 0), text, font=font_small)
    text_width = bbox[2] - bbox[0]
    draw.text(((width - text_width) / 2, height / 2 + 20), text, fill='#666666', font=font_small)
    
    img.save('screenshots/gui_dashboard.png')
    print("✓ Created: screenshots/gui_dashboard.png")
    
    # HTML Report placeholder
    img = Image.new('RGB', (width, height), color='#ffffff')
    draw = ImageDraw.Draw(img)
    
    text = "HTML Security Report"
    bbox = draw.textbbox((0, 0), text, font=font_large)
    text_width = bbox[2] - bbox[0]
    draw.text(((width - text_width) / 2, height / 2 - 40), text, fill='#1e3c72', font=font_large)
    
    text = "(Open generated report in reports/ folder)"
    bbox = draw.textbbox((0, 0), text, font=font_small)
    text_width = bbox[2] - bbox[0]
    draw.text(((width - text_width) / 2, height / 2 + 20), text, fill='#666666', font=font_small)
    
    img.save('screenshots/html_report.png')
    print("✓ Created: screenshots/html_report.png")

def main():
    """Generate all screenshots"""
    print("Generating screenshots for TDRF...\n")
    
    try:
        create_banner()
        create_cli_screenshot()
        create_port_scan_screenshot()
        create_placeholder_images()
        
        print("\n✅ All screenshots generated successfully!")
        print("\nScreenshots created in screenshots/ folder:")
        print("  - banner.png")
        print("  - cli_interface.png")
        print("  - port_scan.png")
        print("  - gui_dashboard.png")
        print("  - html_report.png")
        print("\nNote: For better screenshots, take actual screenshots")
        print("of the running application and replace these placeholders.")
        
    except ImportError:
        print("❌ PIL/Pillow not installed!")
        print("Install with: pip install Pillow")
        print("\nCreating placeholder text files instead...")
        
        os.makedirs('screenshots', exist_ok=True)
        placeholder_text = "Screenshot placeholder - Take actual screenshot and replace this file"
        
        for filename in ['banner.txt', 'cli_interface.txt', 'port_scan.txt', 'gui_dashboard.txt', 'html_report.txt']:
            with open(f'screenshots/{filename}', 'w') as f:
                f.write(placeholder_text)
            print(f"✓ Created placeholder: screenshots/{filename}")

if __name__ == '__main__':
    main()
