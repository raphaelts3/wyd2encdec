program EncDec;

{$mode objfpc}{$H+}

uses
  SysUtils;

const
  KeySize = 512;

function ReadFileToBuffer(const FileName: string; var Buffer: TBytes; var Size: Integer): Boolean;
var
  F: File;
begin
  AssignFile(F, FileName);
  {$I-}
  Reset(F, 1);
  {$I+}
  if IOResult <> 0 then
  begin
    WriteLn('Failed to open file: ', FileName);
    Result := False;
    Exit;
  end;
  Size := FileSize(F);
  SetLength(Buffer, Size);
  BlockRead(F, Buffer[0], Size);
  CloseFile(F);
  Result := True;
end;

procedure Encrypt(var Data: array of Byte; Length: Integer; const Keys: array of Byte);
var
  Off, PacketLength, Key, I, MappedKey, CurrValue: Integer;
begin
  Off := 0;
  while Off < Length do
  begin
    PacketLength := Data[Off] + (Data[Off+1] shl 8);
    Key := Data[Off+2];
    Key := Keys[(Key shl 1) mod KeySize];
    I := Off + 4;
    while I < Off + PacketLength do
    begin
      MappedKey := Keys[((Key mod 256) shl 1) mod KeySize + 1];
      CurrValue := Data[I];
      case I and 3 of
        0: CurrValue := (CurrValue + (MappedKey shl 1)) and 255;
        1: CurrValue := (CurrValue - (MappedKey shr 3)) and 255;
        2: CurrValue := (CurrValue + (MappedKey shl 2)) and 255;
        3: CurrValue := (CurrValue - (MappedKey shr 5)) and 255;
      end;
      Data[I] := CurrValue;
      Inc(Key);
      Inc(I);
    end;
    Off := Off + PacketLength;
  end;
end;

procedure Decrypt(var Data: array of Byte; Length: Integer; const Keys: array of Byte);
var
  Off, PacketLength, Key, I, MappedKey, CurrValue: Integer;
begin
  Off := 0;
  while Off < Length do
  begin
    PacketLength := Data[Off] + (Data[Off+1] shl 8);
    Key := Data[Off+2];
    Key := Keys[Key shl 1];
    I := Off + 4;
    while I < Off + PacketLength do
    begin
      MappedKey := Keys[((Key mod 256) shl 1) mod KeySize + 1];
      CurrValue := Data[I];
      case I and 3 of
        0: CurrValue := (CurrValue - (MappedKey shl 1)) and 255;
        1: CurrValue := (CurrValue + (MappedKey shr 3)) and 255;
        2: CurrValue := (CurrValue - (MappedKey shl 2)) and 255;
        3: CurrValue := (CurrValue + (MappedKey shr 5)) and 255;
      end;
      Data[I] := CurrValue;
      Inc(Key);
      Inc(I);
    end;
    Off := Off + PacketLength;
  end;
end;

procedure WriteBufferToFile(const FileName: string; const Buffer: array of Byte; Size: Integer);
var
  F: File;
begin
  AssignFile(F, FileName);
  {$I-}
  Rewrite(F, 1);
  {$I+}
  if IOResult <> 0 then
  begin
    WriteLn('Failed to write file: ', FileName);
    Exit;
  end;
  BlockWrite(F, Buffer[0], Size);
  CloseFile(F);
end;

var
  Keys: array of Byte;
  EncryptedRaw, DecryptedRaw: array of Byte;
  KeysSize, EncryptedSize, DecryptedSize: Integer;
  Diff, I: Integer;
  Op: string;
begin
  if ParamCount < 4 then
  begin
    WriteLn('Usage: encdec <keys> <enc|dec> <encrypted> <decrypted>');
    Halt(1);
  end;
  if not ReadFileToBuffer(ParamStr(1), Keys, KeysSize) then Halt(2);
  if not ReadFileToBuffer(ParamStr(3), EncryptedRaw, EncryptedSize) then Halt(3);
  if not ReadFileToBuffer(ParamStr(4), DecryptedRaw, DecryptedSize) then Halt(4);
  Op := ParamStr(2);
  if Op = 'enc' then
  begin
    Encrypt(DecryptedRaw, DecryptedSize, Keys);
    WriteBufferToFile('encoded.bin', DecryptedRaw, DecryptedSize);
  end;
  if Op = 'dec' then
  begin
    Decrypt(EncryptedRaw, EncryptedSize, Keys);
    WriteBufferToFile('decoded.bin', EncryptedRaw, EncryptedSize);
  end;
  Diff := 0;
  for I := 0 to EncryptedSize - 1 do
    if (I < DecryptedSize) and (EncryptedRaw[I] <> DecryptedRaw[I]) then Inc(Diff);
  WriteLn(Diff, ' differences');
end.
