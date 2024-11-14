from Encrpytion import DESEncryption
from PDFHandler import PDFHandler
import streamlit as st

def main():
    inputPdf = r"C:\Users\LENOVO\Desktop\DES\final\input.pdf"
    st.title("DES Encryption and Decryption")

    uploaded_file = st.file_uploader("Choose a PDF file", type="pdf")

    if uploaded_file is not None:
        st.write(f"File uploaded: {uploaded_file.name}")
        
        text = PDFHandler.readPdf(inputPdf).replace("’", "'")
        st.text_area("Extracted Text", text, height=300)
        outputEncryptedPdf = "encrypted.pdf"
        outputDecryptedPdf = "decrypted.pdf"
        key = "USMANJAV"


        
        # text = PDFHandler.readPdf(inputPdf).replace("’", "")
        des = DESEncryption()
        # print(f"Original Text: {text}")
        
        encryptedText = des.desEncrypt(plainText=text, key=key)
        PDFHandler.writePdf(outputEncryptedPdf, encryptedText)
        # print(f"Encrypted Text: {encryptedText}")
        decryptedText = des.desDecrypt(encryptedText, key=key)
        PDFHandler.writePdf(outputDecryptedPdf, decryptedText)

if __name__ == "__main__":
    main()
