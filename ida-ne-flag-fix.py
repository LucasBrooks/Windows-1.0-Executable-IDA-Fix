import idaapi
import struct
import os

def getDat(start, length):
  global exe_file
  exe_file.seek(start, 0)
  result = exe_file.read(length)
  return result

def getVal(start, length):
  result = int(struct.unpack('<I', getDat(start, length) + b"\00" * (4 - length))[0])
  return result

exe_name = idaapi.ask_file(0, "", "FILTER *.EXE\nSelect EXE file")
if exe_name is not None and os.path.isfile(exe_name):
  if os.path.getsize(exe_name) >= 64:
    with open(exe_name, "r+b") as exe_file:
      MZ_Magic = getDat(0, 2)
      if MZ_Magic == "MZ":
        NEAddr = getVal(60, 4)
        NE_Magic = getDat(0 + NEAddr, 2)
        if NE_Magic == "NE":
          LinkVer = getVal(2 + NEAddr, 1)
          if LinkVer == 4 or LinkVer == 5:
            SegTableAddr = getVal(34 + NEAddr, 2)
            NumSeg = getVal(28 + NEAddr, 2)
            count = 0
            position = SegTableAddr + NEAddr
            while count < NumSeg:
              thing = getVal(position + 4, 2)
              if '{0:016b}'.format(thing)[2] == "1":
                print("Segment #" + str(count + 1) + ": Issue detected, fixing...")  
                exe_file.seek(position + 4, 0)
                exe_file.write(struct.pack("<H", thing - 8192))
              else:
                print("Segment #" + str(count + 1) + ": Good")
              position = position + 8
              count = count + 1
            idaapi.info("Executable fixed!")
          else:
            idaapi.warning("Not a Windows 1.0 Beta Release+ executable!")
        else:
          idaapi.warning("Not a valid Windows executable!")
      else:
        idaapi.warning("Not a valid executable!")
  else:
    idaapi.warning("File too small!")
else:
  idaapi.warning("File does not exist!")