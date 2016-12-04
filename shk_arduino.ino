

#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN         9           // Configurable, see typical pin layout above
#define SS_PIN          10          // Configurable, see typical pin layout above

#define LED_RED         A2
#define LED_YELLOW      A0
#define LED_GREEN       A1             

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

MFRC522::MIFARE_Key keyA;
MFRC522::MIFARE_Key keyB;

/**
 * Initialize.
 */
void setup() {
    pinMode(LED_RED, OUTPUT);
    pinMode(LED_YELLOW, OUTPUT);
    pinMode(LED_GREEN, OUTPUT);

    Serial.begin(9600); // Initialize serial communications with the PC
    while (!Serial);    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
    SPI.begin();        // Init SPI bus
    mfrc522.PCD_Init(); // Init MFRC522 card
    

    //Serial.println(F("Scan a MIFARE Classic PICC to demonstrate read and write."));
    //Serial.print(F("Using key (for A and B):"));
    //dump_byte_array(keyA.keyByte, MFRC522::MF_KEY_SIZE);
    //Serial.println();
    
    //Serial.println(F("BEWARE: Data will be written to the PICC, in sector #1"));
}

/**
 * Main loop.
 */
void loop() {
    String text = "";

    if (Serial.available() > 0){
        text = Serial.readString();
        if (text.length() < 12) {
            if (text == "OK"){
                setLeds(0, 0, 255);
            } else if (text == "NO_FACE"){
                setLeds(0, 255, 0);
            } else if (text == "NO_NFC"){
                setLeds(255, 0, 0);
            }
            delay(2000);
            setLeds(0, 0, 0);
        }
    }

    // Look for new cards
    if ( ! mfrc522.PICC_IsNewCardPresent())
        return;

    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
        return;

    Serial.println("DETECTED");

    while (Serial.available() <= 0) {
        // nothing to do
    }

    do{
        text = Serial.readString();
    } while(Serial.available() > 0);

    formatKey(text);

    // Show some details of the PICC (that is: the tag/card)
    //Serial.print(F("Card UID:"));
    //dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    //Serial.println();
    //Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    //Serial.println(mfrc522.PICC_GetTypeName(piccType));

    // Check for compatibility
    if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
        return;
    }

    // In this sample we use the second sector,
    // that is: sector #1, covering block #4 up to and including block #7
    byte sector = 4;

    byte firstBlock = 16; 
    byte secondBlock = 17; 
    byte thirdBlock = 18; 
    byte trailerBlock = 19;
    

    
    MFRC522::StatusCode status;

    // Authenticate using key A
    status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &keyA, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.println("UNAUTHORIZED");
    }else{
        readBlock(status, firstBlock);
        readBlock(status, secondBlock);
        readBlock(status, thirdBlock);
        Serial.println();

        // Halt PICC
        mfrc522.PICC_HaltA();
        // Stop encryption on PCD
        mfrc522.PCD_StopCrypto1();
    }


    while (Serial.available() <= 0) {
        // nothing to do
    }

    
}

void setLeds(int red, int yellow, int green){
    analogWrite(LED_RED, red);
    analogWrite(LED_YELLOW, yellow);
    analogWrite(LED_GREEN, green);
}

void clearBuffer(){
    while(Serial.available() > 0){
        Serial.read();
    }
}

void readBlock(MFRC522::StatusCode status, byte blockAddr){
    byte buffer[18];
    byte size = sizeof(buffer);
    status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.println("UNAUTHORIZED");
        clearBuffer();
    }else{
        dump_byte_array(buffer, 16); 
    }
}

void formatKey(String key){
    int j = 0;

    uint8_t b[6];
    char temp[2];
    char msg[13];

    key.toCharArray(msg, 13);
    for (int i = 0; i < 12; i += 2){
        strncpy(temp, &msg[i], 2);

        temp[0] = toupper(temp[0]);    // Convert to upper case
        temp[1] = toupper(temp[1]);

        // Convert hex string to numeric:
        b[j] = (temp[0] <= '9') ? (temp[0] - '0') : (temp[0] - 'A' + 10);
        b[j] *= 16;
        b[j] += (temp[1] <= '9') ? (temp[1] - '0') : (temp[1] - 'A' + 10);

        keyA.keyByte[j] = b[j]; 

        j++;
    }
    // We have the key here
    //dump_byte_array(keyA.keyByte, 6);
}

/**
 * Helper routine to dump a byte array as hex values to Serial.
 */
void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? "0" : "");
        Serial.print(buffer[i], HEX);
    }
    clearBuffer();
}
