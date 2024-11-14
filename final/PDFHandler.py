from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import Paragraph, SimpleDocTemplate
from reportlab.lib.styles import getSampleStyleSheet
import os
from io import BytesIO
import textwrap

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
        buffer = BytesIO()

        c = canvas.Canvas(buffer, pagesize=(width, height))

        font_name = "Helvetica"
        font_size = 12
        c.setFont(font_name, font_size)
        wrapped_text = textwrap.wrap(text, width=80)  

        for line in wrapped_text:
            text_width = c.stringWidth(line, font_name, font_size)
            x_position = (width - text_width) / 2  
            c.drawString(x_position, y_position, line)
            y_position -= 15  
            if y_position < 50:
                c.showPage()
                y_position = 750  
                c.setFont(font_name, font_size)  

        c.save()

        buffer.seek(0)

        return buffer
        