import streamlit as st
import xmlsec
import lxml.etree as ET
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from base64 import b64decode

def validate_xml_signature(xml_content):
    try:
        xml_tree = ET.fromstring(xml_content)
        signature_node = xml_tree.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')

        if signature_node is None:
            return {"success": False, "message": "Signature not found in the XML document."}
        key_info_node = signature_node.find('.//{http://www.w3.org/2000/09/xmldsig#}KeyInfo')
        x509_cert_node = key_info_node.find('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate')

        if x509_cert_node is None:
            return {"success": False, "message": "X509Certificate not found in KeyInfo."}
        x509_cert_data = x509_cert_node.text
        cert_pem = f"-----BEGIN CERTIFICATE-----\n{x509_cert_data}\n-----END CERTIFICATE-----"
        certificate = load_certificate(FILETYPE_PEM, cert_pem)
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_memory(cert_pem, xmlsec.KeyFormat.CERT_PEM, None)
        ctx.key = key
        ctx.verify(signature_node)
        organization = certificate.get_subject().O
        issuer = certificate.get_issuer().O
        valid_to = certificate.get_notAfter().decode("utf-8")
        
        return {
            "success": True,
            "certificateDetail": {
                "organization": organization,
                "issuer": issuer,
                "validTo": valid_to[:8]  
            }
        }

    except Exception as e:
        return {"success": False, "message": str(e)}

st.title("XML Digital Signature Validator")

uploaded_file = st.file_uploader("Upload an XML document", type="xml")

if uploaded_file is not None:
    xml_content = uploaded_file.read()
    result = validate_xml_signature(xml_content)

    if result["success"]:
        st.success("Signature is valid!")
        st.json(result["certificateDetail"])
    else:
        st.error(f"Validation failed: {result['message']}")
