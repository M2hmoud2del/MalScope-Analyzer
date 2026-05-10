import os
import json
import textwrap
import copy
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
        pdf.set_x(10) # Reset cursor
        pdf.cell(0, 10, "1. Executive Summary", ln=True)
        
        pdf.set_font("helvetica", "", 10)
        pdf.set_x(10)
        pdf.cell(0, 6, f"Target File: {filename}", ln=True)
        pdf.set_x(10)
        pdf.cell(0, 6, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        
        # Color-code the verdict based on severity
        if verdict == "MALICIOUS":
            pdf.set_text_color(220, 53, 69) # Red
        elif verdict == "SUSPICIOUS":
            pdf.set_text_color(255, 153, 0) # Orange
        else:
            pdf.set_text_color(40, 167, 69) # Green
            
        pdf.set_x(10)
        pdf.cell(0, 6, f"Final Verdict: {verdict}", ln=True)
        pdf.set_x(10)
        pdf.cell(0, 6, f"Risk Score: {score}/10", ln=True)
        pdf.set_text_color(0, 0, 0) # Reset to black for the rest of the document
        pdf.ln(5)

        # --- Section 2: AI Threat Intelligence ---
        pdf.set_font("helvetica", "B", 12)
        pdf.set_x(10)
        pdf.cell(0, 10, "2. AI Threat Intelligence Summary", ln=True)
        pdf.set_font("helvetica", "", 10)
        
        # Strip unsupported unicode, then forcefully wrap the AI text paragraph by paragraph
        safe_ai_text = str(ai_explanation).encode('latin-1', 'replace').decode('latin-1')
        for paragraph in safe_ai_text.split('\n'):
            # Lowered to 90
            wrapped_p = textwrap.fill(paragraph, width=90, break_long_words=True)
            pdf.set_x(10) 
            # Added align="L" to prevent stretching
            pdf.multi_cell(0, 6, txt=wrapped_p, align="L")
        pdf.ln(5)

       # --- Section 3: Technical Data (Static & Dynamic) ---
        pdf.set_font("helvetica", "B", 12)
        pdf.set_x(10)
        pdf.cell(0, 10, "3. Technical Data", ln=True)
        
        pdf.set_font("helvetica", "I", 10)
        pdf.set_x(10)
        pdf.cell(0, 8, "Static Analysis Findings:", ln=True)
        pdf.set_font("helvetica", "", 9)
        
        for key, val in scan_data.get('static', {}).items():
            # THE PRO FIX: Truncate massive string arrays to save the reader's sanity!
            if key == 'strings' and isinstance(val, dict):
                clean_strings = copy.deepcopy(val)
                if 'general_strings' in clean_strings:
                    gen = clean_strings['general_strings']
                    if 'ascii' in gen and isinstance(gen['ascii'], list) and len(gen['ascii']) > 20:
                        gen['ascii'] = gen['ascii'][:20] + [f"... ({len(gen['ascii']) - 20} more omitted)"]
                    if 'unicode' in gen and isinstance(gen['unicode'], list) and len(gen['unicode']) > 20:
                        gen['unicode'] = gen['unicode'][:20] + [f"... ({len(gen['unicode']) - 20} more omitted)"]
                formatted_val = str(clean_strings)
                
            # Keep the beautiful JSON formatting for hashes and API results
            elif isinstance(val, (dict, list)):
                formatted_val = json.dumps(val, indent=4)
            else:
                formatted_val = str(val)
                
            raw_text = f"    - {key}: {formatted_val}"
            
            for line in raw_text.split('\n'):
                wrapped_text = textwrap.fill(line, width=90, break_long_words=True)
                pdf.set_x(10) 
                pdf.multi_cell(0, 6, txt=wrapped_text, align="L")
            
        pdf.ln(3)
        
        pdf.set_font("helvetica", "I", 10)
        pdf.set_x(10)
        pdf.cell(0, 8, "Dynamic Analysis Findings:", ln=True)
        pdf.set_font("helvetica", "", 9)
        
        for key, val in scan_data.get('dynamic', {}).items():
            # THE PRO FIX: Truncate massive string arrays to save the reader's sanity!
            if key == 'strings' and isinstance(val, dict):
                clean_strings = copy.deepcopy(val)
                if 'general_strings' in clean_strings:
                    gen = clean_strings['general_strings']
                    if 'ascii' in gen and isinstance(gen['ascii'], list) and len(gen['ascii']) > 20:
                        gen['ascii'] = gen['ascii'][:20] + [f"... ({len(gen['ascii']) - 20} more omitted)"]
                    if 'unicode' in gen and isinstance(gen['unicode'], list) and len(gen['unicode']) > 20:
                        gen['unicode'] = gen['unicode'][:20] + [f"... ({len(gen['unicode']) - 20} more omitted)"]
                formatted_val = str(clean_strings)
                
            # Keep the beautiful JSON formatting for hashes and API results
            elif isinstance(val, (dict, list)):
                formatted_val = json.dumps(val, indent=4)
            else:
                formatted_val = str(val)
                
            raw_text = f"    - {key}: {formatted_val}"
            
            for line in raw_text.split('\n'):
                wrapped_text = textwrap.fill(line, width=90, break_long_words=True)
                pdf.set_x(10) 
                pdf.multi_cell(0, 6, txt=wrapped_text, align="L")

        # --- Save the Output ---
        safe_filename = filename.replace(" ", "_").replace(".", "_")
        output_file = os.path.join(self.reports_dir, f"MalScope_Report_{safe_filename}.pdf")
        pdf.output(output_file)
        
        return output_file