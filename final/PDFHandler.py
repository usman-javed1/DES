from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import Paragraph, SimpleDocTemplate
from reportlab.lib.styles import getSampleStyleSheet
import os

class PDFHandler:
    @staticmethod
    def readPdf(filePath):
        reader = PdfReader(filePath)
        text = ""
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text
        return text

        # reader = PdfReader(file)
        # text = ""
        
        # # Loop through each page and append text
        # for page in reader.pages:
        #     text += page.extract_text() or ""  # Append page text (or empty if None)
        
        # return text

    @staticmethod
    def writePdf(filePath, text, width=612, height=792):  
        temp_pdf_path = "temp_output.pdf"

        print("text is ", text)
        
        doc = SimpleDocTemplate(temp_pdf_path, pagesize=(width, height))
        styles = getSampleStyleSheet()
        style = styles["BodyText"]
        
        paragraph = Paragraph(text, style)
        doc.build([paragraph])
        
        temp_reader = PdfReader(temp_pdf_path)
        writer = PdfWriter()
        
        for page in temp_reader.pages:
            writer.add_page(page)
        
        with open(filePath, "wb") as output_pdf:
            writer.write(output_pdf)
        
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)

# Example usage:
# text = PDFHandler.readPdf("input.pdf")
# PDFHandler.writePdf("output.pdf", "Sample text to include in PDF with proper line wrapping.")
