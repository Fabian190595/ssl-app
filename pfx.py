import tkinter as tk
from tkinter import simpledialog, filedialog, messagebox
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto

# Function to generate a CSR file
def generate_csr(common_name):
    # Predefined values
    country = "MY"
    locality = "KL"
    organization_name = "kk"
    organizational_unit = "ll"

    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create CSR
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())

    # Save the private key and CSR to files
    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("certificate_request.csr", "wb") as csr_file:
        csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

    print("CSR and private key have been generated.")
    messagebox.showinfo("Success", "CSR file generated successfully.")


# Function to view and validate the content of a PFX file
def view_pfx():
    file_path = filedialog.askopenfilename(title="Select PFX File", filetypes=[("PFX files", "*.pfx")])
    
    if file_path:
        # Prompt for password
        password = simpledialog.askstring("Password", "Enter password for the PFX file:", show='*')

        if password is None:  # User canceled the password input
            return

        try:
            # Load the PFX file with the provided password
            with open(file_path, 'rb') as f:
                pfx_data = f.read()
            
            # Load the PFX file into OpenSSL with password
            pfx = crypto.load_pkcs12(pfx_data, password.encode())  # Convert password to bytes
            cert = pfx.get_certificate()
            chain = pfx.get_ca_certificates()
            private_key = pfx.get_privatekey()

            # Extract certificate information
            cert_subject = cert.get_subject()
            cert_issuer = cert.get_issuer()
            cert_not_before = cert.get_notBefore().decode('utf-8')
            cert_not_after = cert.get_notAfter().decode('utf-8')

            # Display information
            cert_info = f"Certificate Subject: {cert_subject}\n" \
                        f"Certificate Issuer: {cert_issuer}\n" \
                        f"Valid From: {cert_not_before}\n" \
                        f"Valid To: {cert_not_after}\n"

            # Check if there is a private key available
            private_key_info = ""
            if private_key:
                private_key_info = f"Private Key: Available\n"
            else:
                private_key_info = f"Private Key: Not Available\n"

            # Check the certificate chain
            chain_info = "Certificate Chain:\n"
            if chain:
                for idx, c in enumerate(chain):
                    chain_info += f"  - Certificate {idx+1}: {c.get_subject()}\n"
            else:
                chain_info += "  No additional certificates in the chain.\n"

            # Combine all information to display
            full_info = cert_info + private_key_info + chain_info
            print(full_info)

            # Show information in a messagebox
            messagebox.showinfo("PFX File Content", full_info)

        except Exception as e:
            print(f"Error loading PFX file: {e}")
            messagebox.showerror("Error", "Error loading the PFX file. Please check the password and try again.")
    else:
        print("No file selected.")


# Function to create a PFX file from .cer, .key, and root certificate
def create_pfx():
    # Select the .cer certificate file
    cert_file = filedialog.askopenfilename(title="Select Certificate (.cer) File", filetypes=[("Certificate files", "*.cer")])
    if not cert_file:
        messagebox.showerror("Error", "You must select a .cer certificate file.")
        return

    # Select the .key private key file
    key_file = filedialog.askopenfilename(title="Select Private Key (.key) File", filetypes=[("Key files", "*.key")])
    if not key_file:
        messagebox.showerror("Error", "You must select a .key private key file.")
        return

    # Select the root/intermediate certificate file
    root_cert_file = filedialog.askopenfilename(title="Select Root/Intermediate Certificate (.cer) File", filetypes=[("Certificate files", "*.cer")])
    if not root_cert_file:
        messagebox.showerror("Error", "You must select a root/intermediate certificate file.")
        return

    # Prompt for a password to protect the PFX file
    password = simpledialog.askstring("Password", "Enter password to protect the PFX file:", show='*')
    if not password:
        messagebox.showerror("Error", "Password is required to create a PFX file.")
        return

    # Ask for the filename to save the PFX file
    output_file = filedialog.asksaveasfilename(defaultextension=".pfx", 
                                               filetypes=[("PFX files", "*.pfx")], 
                                               title="Save PFX file as")
    if not output_file:
        messagebox.showerror("Error", "Please provide a valid output filename.")
        return

    try:
        # Read in the certificate, private key, and root certificate files
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
        with open(key_file, 'rb') as f:
            key_data = f.read()
        with open(root_cert_file, 'rb') as f:
            root_cert_data = f.read()

        # Create the PFX file (PKCS#12)
        pfx = crypto.PKCS12()
        pfx.set_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, cert_data))
        pfx.set_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, key_data))
        pfx.set_ca_certificates([crypto.load_certificate(crypto.FILETYPE_PEM, root_cert_data)])

        # Export the PFX file with the provided password
        pfx_data = pfx.export(passphrase=password.encode())

        # Save the PFX file
        with open(output_file, "wb") as pfx_file:
            pfx_file.write(pfx_data)

        messagebox.showinfo("Success", f"PFX file created successfully at {output_file}")

    except Exception as e:
        print(f"Error creating PFX file: {e}")
        messagebox.showerror("Error", f"Error creating PFX file: {e}")


# Function to prompt for Common Name input and generate CSR
def ask_common_name():
    common_name = simpledialog.askstring("Input", "Enter Common Name:")
    if common_name:
        generate_csr(common_name)


# Main application GUI
def main():
    root = tk.Tk()
    root.title("Certificate Management Application")
    root.geometry("400x300")

    # Label for instructions
    instructions = tk.Label(root, text="Choose an action to generate or manage certificates.", anchor='w', padx=10)
    instructions.pack(pady=10, anchor='w')

    # Button to Generate CSR
    csr_button = tk.Button(root, text="Generate CSR", command=ask_common_name, width=30)
    csr_button.pack(pady=10)

    # Button to View PFX
    pfx_button = tk.Button(root, text="View PFX", command=view_pfx, width=30)
    pfx_button.pack(pady=10)

    # Button to Create PFX
    pfx_create_button = tk.Button(root, text="Create PFX", command=create_pfx, width=30)
    pfx_create_button.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()
