import pefile
import datetime

def analyze_pe(file_path):
    """
    Analyzes a Portable Executable (PE) file to detect suspicious characteristics.
    """
    result = {
        "is_pe": False,
        "machine_type": None,
        "compile_date": None,
        "sections": [],
        "suspicious_indicators": []
    }
    
    try:
        pe = pefile.PE(file_path)
        result["is_pe"] = True
        
        # 1. Header Analysis
        # Machine Type
        machine_hex = hex(pe.FILE_HEADER.Machine)
        machine_type = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, machine_hex)
        result["machine_type"] = machine_type
        
        # Compile Date
        timestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_date = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            result["compile_date"] = compile_date
        except Exception:
            result["compile_date"] = "Invalid Date"
            
        # 2. Sections Analysis & Entry Point check
        standard_sections = ['.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc', '.edata', '.idata', '.pdata', '.tls', '.debug']
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section = None
        
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            entropy = section.get_entropy()
            
            result["sections"].append({
                "name": sec_name,
                "entropy": round(entropy, 2)
            })
            
            # Suspicious Indicator: High entropy
            if entropy > 7.0:
                result["suspicious_indicators"].append(f"High entropy ({entropy:.2f}) in section '{sec_name}' (Possible packing/encryption)")
                
            # Suspicious Indicator: Unusual section names
            if sec_name.lower() not in [s.lower() for s in standard_sections] and sec_name:
                result["suspicious_indicators"].append(f"Unusual section name: '{sec_name}'")
                
            # Check if this section contains the entry point
            if section.VirtualAddress <= entry_point < (section.VirtualAddress + section.Misc_VirtualSize):
                ep_section = sec_name
                
        # 3. Entry Point in non-standard section
        if ep_section and ep_section.lower() not in ['.text', 'code']:
            result["suspicious_indicators"].append(f"Entry point located in non-standard section: '{ep_section}'")
        elif not ep_section:
            result["suspicious_indicators"].append("Could not locate Entry Point in any specific section")
            
        # 4. Few Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            num_imported_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
            if num_imported_dlls < 3:
                result["suspicious_indicators"].append(f"Very few imports ({num_imported_dlls} DLLs). Common in small droppers/packers")
        else:
            result["suspicious_indicators"].append("No imports found (Highly suspicious)")
            
        pe.close()
            
    except pefile.PEFormatError:
        return {"error": "Not a valid PE file or corrupted"}
    except Exception as e:
        return {"error": str(e)}
        
    return result
