### UnPAZ \<input file\> \<commands\>

*\<input file\>*:  name of .meta or .paz file (default: pad00000.meta)  
*\<commands\>*:  
*-f \<mask\>*:  Filter, this argument must be followed by mask. Mask supports wildcards * and ?.  
*-o \<path\>*:  Output folder, this argument must be followed by path.  
*-h*:  Print this help text.  
*-l*:  List file names without extracting them.  
*-n*:  No folder structure, extract files directly to output folder.  
*-y*:  Yes to all questions (creating folders, overwritting files).  
*-q*:  Quiet (limit printed messages to file names).  
*-c*:  Compressed (decrypt only, don't decompress).  

### Examples:
```
UnPAZ pad00001.paz -f *.luac
```
```
UnPAZ pad00000.meta -y -f *languagedata_??.txt -o Extracted
```
```
UnPAZ pad00000.meta -l
```
