#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>
#include <windows.h>

#include <iomanip>
#include <set>

//-----------------------------------------
// boot.h 에 정의된 값 (ASCII)
//-----------------------------------------
#define BOOT_FRAME_START '$'
#define BOOT_CMD_IDENT   '0'
#define BOOT_CMD_SETUP   '1'
#define BOOT_CMD_ERASE   '2'
#define BOOT_CMD_WRITE   '3'
#define BOOT_CMD_VERIFY  '4'
#define BOOT_CMD_LOCK    '5'
#define BOOT_CMD_RUNAPP  '6'
#define BOOT_ACK_REPLY   '@'
#define BOOT_ERR_BADID   'B'


struct HexRecord {
    uint8_t length;            // 데이터 바이트 수
    uint16_t address;          // 16비트 시작 주소
    uint8_t recordType;        // 레코드 타입 (00: 데이터, 01: EOF)
    std::vector<uint8_t> data; // 데이터 바이트들
    uint8_t checksum;
};

std::string vectorToHexString(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (uint8_t byte : data) {
        oss << std::setw(2) << static_cast<int>(byte) << " ";
    }
    return oss.str();
}

//-----------------------------------------
// (1) 시리얼 포트 열기 함수
//-----------------------------------------
HANDLE openSerialPort(const std::string& portName, DWORD baudRate = 115200)
{
    HANDLE hSerial = CreateFileA(
        portName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, // exclusive access
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hSerial == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Error opening " << portName << "\n";
        return INVALID_HANDLE_VALUE;
    }

    // 시리얼 설정
    DCB dcb = {0};
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(hSerial, &dcb))
    {
        std::cerr << "GetCommState failed.\n";
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }
    dcb.BaudRate = baudRate;
    dcb.ByteSize = 8;
    dcb.StopBits = ONESTOPBIT;
    dcb.Parity   = NOPARITY;
    if (!SetCommState(hSerial, &dcb))
    {
        std::cerr << "SetCommState failed.\n";
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }

    // 타임아웃
    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout         = 0;
    timeouts.ReadTotalTimeoutConstant    = 0;
    timeouts.ReadTotalTimeoutMultiplier  = 0;
    timeouts.WriteTotalTimeoutConstant   = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;
    if (!SetCommTimeouts(hSerial, &timeouts))
    {
        std::cerr << "SetCommTimeouts failed.\n";
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }

    PurgeComm(hSerial, PURGE_TXCLEAR | PURGE_RXCLEAR);

    std::cout << portName << " opened at " << baudRate << " baud.\n";
    return hSerial;
}

//-----------------------------------------
// (2) 프레임 전송 + 부트로더 1바이트 응답 수신
//-----------------------------------------
bool sendFrameAndGetReply(HANDLE hSerial, 
                          const std::vector<uint8_t>& payload, 
                          uint8_t &reply)
{
    // 1) 프레임 구성: $ LEN DATA... CHECKSUM
    uint8_t len = (uint8_t)payload.size();
    uint8_t checksum = 0;
    checksum ^= len;
    for (auto b : payload) {
        checksum ^= b;
    }

    // 전송 버퍼 만들기
    std::vector<uint8_t> txFrame;
    txFrame.reserve(2 + len + 1); // '$', len, payload, checksum
    txFrame.push_back(BOOT_FRAME_START); // '$'
    txFrame.push_back(len);
    for (auto b : payload) {
        txFrame.push_back(b);
    }
    txFrame.push_back(checksum);

    // 2) WriteFile 로 프레임 전송
    DWORD written = 0;
    BOOL ok = WriteFile(hSerial, txFrame.data(), (DWORD)txFrame.size(), &written, NULL);
    if (!ok || written != txFrame.size())
    {
        std::cerr << "WriteFile failed or incomplete.\n";
        return false;
    }
    std::cout << "[SEND] Data : " << vectorToHexString(txFrame) << std::endl;

    // 3) 1바이트 응답 수신
    DWORD bytesRead = 0;
    uint8_t rxByte = 0xFF;
    ok = ReadFile(hSerial, &rxByte, 1, &bytesRead, NULL);
    if (!ok)
    {
        std::cerr << "ReadFile failed.\n";
        return false;
    }
    if (bytesRead == 0)
    {
        std::cerr << "No response (timeout).\n";
        return false;
    }

    reply = rxByte;
    std::cout << rxByte << std::endl;
    return true;
}



HexRecord parseHexLine(const std::string &line) {
    HexRecord rec = {};
    if (line.empty() || line[0] != ':') {
        return rec;
    }
    
    // 각 바이트를 2자리씩 파싱
    size_t byteCount = (line.length() - 1) / 2;  // 콜론 제외
    std::vector<uint8_t> bytes;
    bytes.reserve(byteCount);
    for (size_t i = 1; i < line.length(); i += 2) {
        std::string byteStr = line.substr(i, 2);
        uint8_t value = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        bytes.push_back(value);
    }
    
    if (bytes.size() < 5) {  // 최소: Length, Address(2), RecordType, Checksum
        return rec;
    }
    rec.length = bytes[0];
    rec.address = (static_cast<uint16_t>(bytes[1]) << 8) | bytes[2];
    rec.recordType = bytes[3];
    // 데이터 바이트들: index 4부터 index (4 + length - 1)
    for (size_t i = 0; i < rec.length; i++) {
        rec.data.push_back(bytes[4 + i]);
    }
    rec.checksum = bytes[4 + rec.length];
    // (체크섬 검증은 생략)
    return rec;
}


bool loadHexFile(const std::string &filename, std::vector<HexRecord> &records) {
    std::ifstream ifs(filename);
    if (!ifs) {
        std::cerr << "Cannot open HEX file: " << filename << "\n";
        return false;
    }
    std::string line;
    uint32_t extendedAddress = 0;  // 상위 16비트 (기본 0x0000)
    
    while (std::getline(ifs, line)) {
        HexRecord rec = parseHexLine(line);
        if (rec.recordType == 0x04) {
            // Extended Linear Address record: 데이터 2바이트를 상위 16비트 주소로 사용
            if (rec.data.size() >= 2) {
                extendedAddress = (static_cast<uint32_t>(rec.data[0]) << 8) | rec.data[1];
            }
            continue;
        } else if (rec.recordType == 0x00) { // 데이터 레코드
            // 최종 주소 = (extendedAddress << 16) | rec.address
            // (일반적으로 EFM8는 16비트 주소 공간을 사용하므로, extendedAddress는 0x0000로 설정되어 있어야 함)
            // 여기서는 계산하되, 만약 extendedAddress가 0이 아니라면 사용자 애플리케이션이 16비트 주소 범위를 넘어갈 수 있음
            uint16_t effectiveAddress = static_cast<uint16_t>((extendedAddress << 16) | rec.address);
            rec.address = effectiveAddress;  // 사용자 애플리케이션의 주소로 사용
            records.push_back(rec);
        } else if (rec.recordType == 0x01) { // EOF
            break;
        }
    }
    return true;
}

//-----------------------------------------
// (3) 메인: IDENT 명령을 예로 테스트
//-----------------------------------------
int main()
{
    std::string comPort = "COM5";
    DWORD baudRate = 115200;

    // 1) Open Serial Port
    HANDLE hSerial = openSerialPort(comPort, baudRate);
    if (hSerial == INVALID_HANDLE_VALUE){
        return -1;
    }

    uint8_t data = '1';  // for baudRate setting, send any 1byte data
    DWORD bytesWritten = 0;
    if (!WriteFile(hSerial, &data, 1, &bytesWritten, NULL)) {
        std::cerr << "WriteFile failed.\n";
    }
    std::cout << "[INFO] Set baudRate Done\n";

    // 2) Check IDENT 명령 준비
    //    [ '0'(0x30), ID_LSB, ID_MSB ]
    //    BL_DERIVATIVE_ID = 0x3000 | DEVICE_DERIVID
    //    예) DEVICE_DERIVID가 0x41이면 => 0x3041
    //        => LSB=0x41, MSB=0x30
    uint8_t cmd = BOOT_CMD_IDENT;  // '0'
    uint8_t idMSB = 0x30;         // 가정
    uint8_t idLSB = 0x01;         // 가정
    std::vector<uint8_t> payload;
    payload.push_back(cmd);   // '0'
    payload.push_back(idMSB);
    payload.push_back(idLSB);

    std::cout << "[INFO] Check IDENT \n";
    uint8_t reply = 0;
    if (!sendFrameAndGetReply(hSerial, payload, reply)){
        std::cerr << "IDENT frame send or reply failed.\n";
        CloseHandle(hSerial);
        return -1;
    }

    // Define flash page size (specific to your device, usually 512 bytes for EFM8BB1)
    constexpr uint16_t FLASH_PAGE_SIZE = 512;

    // load hex file and send
    std::vector<HexRecord> hexRecords;
    if (!loadHexFile("EFM8BB1_Blinky.hex", hexRecords)) {
        std::cerr << "Failed to load HEX file.\n";
        CloseHandle(hSerial);
        return -1;
    }
    std::cout << "Loaded " << hexRecords.size() << " data records from HEX file.\n";
    std::set<uint16_t> erasedPages;
    for (const HexRecord &rec : hexRecords) {
            // Calculate the start page of the current address
    uint16_t pageStartAddress = (rec.address / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;

    

        std::vector<uint8_t> writePayload;
        writePayload.push_back(BOOT_CMD_WRITE); // '3' = WRITE 명령
        // 부트로더가 내부에서 역순 저장하는 특성을 고려하여,
        // 주소 전송 시 [addrHigh, addrLow] 순서로 전송 (BL 코드에 따라 조정)
        uint8_t addrHigh = static_cast<uint8_t>(rec.address >> 8);
        uint8_t addrLow  = static_cast<uint8_t>(rec.address & 0xFF);
        writePayload.push_back(addrHigh);
        writePayload.push_back(addrLow);

        // 데이터 바이트 추가
        for (uint8_t b : rec.data) {
            writePayload.push_back(b);
        }

        uint8_t reply = 0;
        if (!sendFrameAndGetReply(hSerial, writePayload, reply)) {
            std::cerr << "WRITE command failed at address 0x" 
                      << std::hex << rec.address << "\n";
            // 필요시 재시도 처리
            continue;
        }
        if (reply != BOOT_ACK_REPLY) {
            std::cerr << "WRITE returned error at address 0x" 
                      << std::hex << rec.address << ": " << (int)reply << "\n";
        } else {
            std::cout << "WRITE OK for address 0x" << std::hex << rec.address << "\n";
        }
    }

    // 5. verigy 명령 전송: 모든 업데이트 완료 후 사용자 애플리케이션 실행
#if 0
    std::cout << "[Send] BOOT_CMD_VERIFY" <<"\n";
    std::vector<uint8_t> VeriftPayload;
    VeriftPayload.push_back(BOOT_CMD_VERIFY); // '6'
    reply = 0;
    if (!sendFrameAndGetReply(hSerial, VeriftPayload, reply)) {
        std::cerr << "BOOT_CMD_VERIFY command failed.\n";
        CloseHandle(hSerial);
        return -1;
    }
#endif

    // 5. RUNAPP 명령 전송: 모든 업데이트 완료 후 사용자 애플리케이션 실행

    std::cout << "[Send] RUNAPP CMD" <<"\n";
    std::vector<uint8_t> runPayload;
    runPayload.push_back(BOOT_CMD_RUNAPP); // '6'
    reply = 0;
    if (!sendFrameAndGetReply(hSerial, runPayload, reply)) {
        std::cerr << "RUNAPP command failed.\n";
        CloseHandle(hSerial);
        return -1;
    }


    // 5) 종료
    CloseHandle(hSerial);
    return 0;
}