from Encrpytion import DESEncryption
from PDFHandler import PDFHandler
import streamlit as st 

def main():
    st.title("DES Encryption and Decryption")

    # Initialize session state variables
    if "boolean_var" not in st.session_state:
        st.session_state.boolean_var = False
    if "file_name" not in st.session_state:
        st.session_state.file_name = None
    if "text_content" not in st.session_state:
        st.session_state.text_content = ""

    # Toggle between Encryption and Decryption
    option = st.radio("Select Mode:", ("Encryption", "Decryption"))

    if option == "Encryption":
        st.session_state.boolean_var = True
    elif option == "Decryption":
        st.session_state.boolean_var = False

    # File upload section
    uploaded_file = st.file_uploader("Choose a PDF file", type="pdf")

    if uploaded_file is not None:
        st.write(f"File uploaded: {uploaded_file.name}")

        # Read and extract text from the uploaded PDF
        text = PDFHandler.readPdf(uploaded_file).replace("’", "'")

        # Update the text content if a new file is uploaded
        if st.session_state.file_name != uploaded_file.name:
            st.session_state.text_content = text
            st.session_state.file_name = uploaded_file.name  # Update the file name in session state

        # Display text area to allow edits and update the session state
        edited_text = st.text_area("Extracted Text", st.session_state.text_content, height=300)
        st.session_state.text_content = edited_text

        # Set paths and encryption key
        outputEncryptedPdf = "encrypted.pdf"
        outputDecryptedPdf = "decrypted.pdf"
        key = "USMANJAV"
        des = DESEncryption()

        # Encrypt or decrypt based on the mode
        if st.session_state.boolean_var:
            # Encryption
            encryptedText = des.desEncrypt(plainText=st.session_state.text_content, key=key)
            pdf_buffer = PDFHandler.writePdf(outputEncryptedPdf, encryptedText)
            st.write("Encryption successful.")
            st.write(f"{encryptedText}")
            st.download_button(
                label="Download Encrypted PDF",
                data=pdf_buffer,
                file_name="encrypted_file.pdf",
                mime="application/pdf"
            )
        else:
            # Decryption
            decryptedText = des.desDecrypt(st.session_state.text_content, key=key)
            pdf_buffer = PDFHandler.writePdf(outputDecryptedPdf, decryptedText)

            st.download_button(
                label="Download Decrypted PDF",
                data=pdf_buffer,
                file_name="decrypted_file.pdf",
                mime="application/pdf"
            )

if __name__ == "__main__":
    main()
