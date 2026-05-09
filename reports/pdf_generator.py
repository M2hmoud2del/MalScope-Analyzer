import os
from fpdf import FPDF
from datetime import datetime

class MalwareReport(FPDF):
    def header(self):
        # Create a professional, red-themed header for the tool
        self.set_font("helvetica", "B", 15)
        self.set_text_color(220, 53, 69) # Red color
        self.cell(0, 10, "MalScope - Automated Malware Analysis Report", align="C", ln=True)
        self.ln(5)

    def footer(self):
        # Add page numbers to the bottom of every page
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128) # Gray color
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

class ReportGenerator:
    def __init__(self):
        # Automatically create a folder for reports if it doesn't exist
        self.reports_dir = "generated_reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_pdf(self, scan_data, ai_explanation):
        pdf = MalwareReport()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        filename = scan_data.get('file', 'Unknown_File')
        verdict = str(scan_data.get('verdict', 'Unknown')).upper()
        score = scan_data.get('score', 0)

        # --- Section 1: Executive Summary ---
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "1. Executive Summary", ln=True)
        
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 6, f"Target File: {filename}", ln=True)
        pdf.cell(0, 6, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        
        # Color-code the verdict based on severity
        if verdict == "MALICIOUS":
            pdf.set_text_color(220, 53, 69) # Red
        elif verdict == "SUSPICIOUS":
            pdf.set_text_color(255, 153, 0) # Orange
        else:
            pdf.set_text_color(40, 167, 69) # Green
            
        pdf.cell(0, 6, f"Final Verdict: {verdict}", ln=True)
        pdf.cell(0, 6, f"Risk Score: {score}/100", ln=True)
        pdf.set_text_color(0, 0, 0) # Reset to black for the rest of the document
        pdf.ln(5)

        # --- Section 2: AI Threat Intelligence ---
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "2. AI Threat Intelligence Summary", ln=True)
        pdf.set_font("helvetica", "", 10)
        
        # Security measure: Strip unsupported unicode (like emojis) that would crash the PDF builder
        safe_ai_text = str(ai_explanation).encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 6, safe_ai_text)
        pdf.ln(5)

        # --- Section 3: Technical Data (Static & Dynamic) ---
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "3. Technical Data", ln=True)
        
        pdf.set_font("helvetica", "I", 10)
        pdf.cell(0, 8, "Static Analysis Findings:", ln=True)
        pdf.set_font("helvetica", "", 9)
        for key, val in scan_data.get('static', {}).items():
            pdf.cell(10) # Add an indent
            pdf.cell(0, 6, f"- {key}: {val}", ln=True)
            
        pdf.ln(3)
        
        pdf.set_font("helvetica", "I", 10)
        pdf.cell(0, 8, "Dynamic Analysis Findings:", ln=True)
        pdf.set_font("helvetica", "", 9)
        for key, val in scan_data.get('dynamic', {}).items():
            pdf.cell(10) # Add an indent
            # Convert list outputs to strings so they fit cleanly
            pdf.cell(0, 6, f"- {key}: {str(val)}", ln=True)

        # --- Save the Output ---
        safe_filename = filename.replace(" ", "_").replace(".", "_")
        output_file = os.path.join(self.reports_dir, f"MalScope_Report_{safe_filename}.pdf")
        pdf.output(output_file)
        
        return output_file