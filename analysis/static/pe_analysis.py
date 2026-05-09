import pefile
import datetime

def analyze_pe(file_path):
    """
    Analyzes a PE file to extract headers, sections, imports, exports,
    signatures, resources, and identifies suspicious characteristics.
    """
    result = {
        "is_pe": False,
        "error": None,
        "imphash": "",
        "machine_type": None,
        "compile_time": None,
        "sections": [],
        "imports_exports": {
            "imports": {},
            "exports": []
        },
        "signature": {
            "signed": False,
            "details": None
        },
        "packer_info": {
            "detected": False,
            "packers": []
        },
        "resources": [],
        "suspicious_indicators": []
    }
    
    try:
        pe = pefile.PE(file_path)
        result["is_pe"] = True
        
        try:
            result["imphash"] = pe.get_imphash() or ""
        except Exception:
            result["imphash"] = ""
        
        # 1. Machine Type
        machine_hex = hex(pe.FILE_HEADER.Machine)
        result["machine_type"] = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, machine_hex)
        
        # 2. Compile Time
        timestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            result["compile_time"] = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            result["compile_time"] = "Invalid Date"
            
        # 3. Sections & Advanced Packer Detection
        standard_sections = ['.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc', '.edata', '.idata', '.pdata', '.tls', '.debug']
        known_packers = {
            '.upx0': 'UPX', '.upx1': 'UPX', '.upx2': 'UPX',
            '.aspack': 'ASPack', '.adata': 'ASPack',
            'MPRESS1': 'MPRESS', 'MPRESS2': 'MPRESS',
            '.enigma1': 'Enigma', '.enigma2': 'Enigma',
            '.themida': 'Themida', '.vmp0': 'VMProtect', '.vmp1': 'VMProtect'
        }
        
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section = None
        
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            entropy = section.get_entropy()
            
            result["sections"].append({
                "name": sec_name,
                "entropy": round(entropy, 2),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData
            })
            
            # Packer Detection (Signature-based)
            for pack_sig, pack_name in known_packers.items():
                if pack_sig.lower() in sec_name.lower():
                    if pack_name not in result["packer_info"]["packers"]:
                        result["packer_info"]["packers"].append(pack_name)
                        result["packer_info"]["detected"] = True
            
            # Suspicious Indicator: High entropy
            if entropy > 7.0:
                result["suspicious_indicators"].append(f"High entropy ({entropy:.2f}) in section '{sec_name}' (Possible packing/encryption)")
                
            # Suspicious Indicator: Unusual section names
            if sec_name.lower() not in [s.lower() for s in standard_sections] and sec_name:
                result["suspicious_indicators"].append(f"Unusual section name: '{sec_name}'")
                
            # Check if this section contains the entry point
            if section.VirtualAddress <= entry_point < (section.VirtualAddress + section.Misc_VirtualSize):
                ep_section = sec_name
                
        # 4. Entry Point checks
        if ep_section and ep_section.lower() not in ['.text', 'code', '']:
            result["suspicious_indicators"].append(f"Entry point located in non-standard section: '{ep_section}'")
        elif not ep_section:
            result["suspicious_indicators"].append("Could not locate Entry Point in any specific section")
            
        # 5. Imports Analysis (IAT)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            num_imported_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
            if num_imported_dlls < 3:
                result["suspicious_indicators"].append(f"Very few imports ({num_imported_dlls} DLLs). Common in small droppers/packers")
                
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore') if entry.dll else "Unknown"
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode('utf-8', errors='ignore'))
                    else:
                        funcs.append(f"Ordinal[{imp.ordinal}]")
                result["imports_exports"]["imports"][dll_name] = funcs
        else:
            result["suspicious_indicators"].append("No imports found (Highly suspicious)")
            
        # 6. Exports Analysis (EAT)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result["imports_exports"]["exports"].append(exp.name.decode('utf-8', errors='ignore'))
                    
        # 7. Digital Signature Verification
        try:
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            if security_dir.VirtualAddress > 0 and security_dir.Size > 0:
                result["signature"]["signed"] = True
                result["signature"]["details"] = "Signature block present (Verification requires further OS parsing)"
        except IndexError:
            pass # No security directory
            
        # 8. Resource Analysis (.rsrc)
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'name') and resource_type.name is not None:
                    name = str(resource_type.name)
                else:
                    name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, f"UNKNOWN ({resource_type.struct.Id})")
                
                # Count resources of this type
                count = len(resource_type.directory.entries) if hasattr(resource_type, 'directory') else 0
                result["resources"].append({"type": name, "count": count})

        pe.close()
            
    except pefile.PEFormatError:
        result["error"] = "Not a valid PE file or corrupted"
    except Exception as e:
        result["error"] = str(e)
        
    return result
