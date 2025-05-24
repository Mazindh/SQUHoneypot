import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sys
# Gmail SMTP settings
smtp_server = "smtp.gmail.com"
smtp_port = 587

# Your Gmail credentials
gmail_user = "squhoneypot@gmail.com"
gmail_app_password = "xeprlmllymznykkl"  

# Email details
sender_email = gmail_user
receiver_email = "squhoneypot@gmail.com"
subject = sys.argv[1] #"Test Email via Gmail SMTP"
body = sys.argv[2] #"Hello! This is a test email sent using Gmail SMTP with an App Password."

# Create the email message
msg = MIMEMultipart()
msg["From"] = sender_email
msg["To"] = receiver_email
msg["Subject"] = subject
msg.attach(MIMEText(body, "plain"))

# Send the email
try:
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Secure the connection
        server.login(gmail_user, gmail_app_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        #server.sendmail(sender_email, "mazinalduhli@gmail.com", msg.as_string())
        print("Email sent successfully via Gmail SMTP!")
except Exception as e:
    print(f"Failed to send email: {e}")
