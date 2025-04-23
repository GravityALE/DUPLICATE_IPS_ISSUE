import streamlit as st
import paramiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
from io import BytesIO
import logging
from datetime import datetime

# Configuración del sistema de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkDeviceScanner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.ssh_timeout = 10
        self.command_timeout = 15
        self.max_workers = 10  # Reducido para logs más ordenados
        
    def log_to_streamlit(self, message, level="info"):
        """Registra mensajes en Streamlit y en el logger"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"
        
        # Niveles de log
        if level == "error":
            logger.error(formatted_msg)
            st.error(formatted_msg)
        elif level == "warning":
            logger.warning(formatted_msg)
            st.warning(formatted_msg)
        elif level == "success":
            logger.info(formatted_msg)
            st.success(formatted_msg)
        else:
            logger.info(formatted_msg)
            st.info(formatted_msg)
        
        # También imprimir en consola (visible al ejecutar streamlit run)
        print(formatted_msg)

    def connect_to_device(self, device_ip, device_type):
        """Establece conexión SSH con el dispositivo"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.log_to_streamlit(f"Conectando a {device_ip} ({device_type})...", "info")
            ssh.connect(device_ip, 
                       username=self.username, 
                       password=self.password, 
                       timeout=self.ssh_timeout,
                       banner_timeout=30,
                       look_for_keys=False,
                       allow_agent=False)
            self.log_to_streamlit(f"Conexión exitosa a {device_ip}", "success")
            return ssh
        except socket.timeout:
            self.log_to_streamlit(f"Timeout al conectar a {device_ip} ({device_type})", "warning")
            return None
        except Exception as e:
            self.log_to_streamlit(f"Error al conectar a {device_ip} ({device_type}): {str(e)}", "warning")
            return None

    def execute_command(self, ssh, command, device_ip):
        """Ejecuta un comando y devuelve la salida"""
        try:
            self.log_to_streamlit(f"Ejecutando en {device_ip}: {command}", "info")
            stdin, stdout, stderr = ssh.exec_command(command, timeout=self.command_timeout)
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            
            if error and "Invalid input detected" not in error:
                self.log_to_streamlit(f"Error en {device_ip}: {error}", "warning")
                return None, error
            return output, None
        except Exception as e:
            self.log_to_streamlit(f"Error ejecutando comando en {device_ip}: {str(e)}", "warning")
            return None, str(e)

    def check_duplicate_ip(self, device_ip, device_type, target_ip):
        """Verifica si la IP está en el dispositivo"""
        ssh = self.connect_to_device(device_ip, device_type)
        if not ssh:
            return device_ip, device_type, None, f"Error de conexión a {device_ip}"
        
        try:
            # Determinar el comando según el tipo de dispositivo
            if 'huawei' in device_type.lower():
                command = f"display ip routing-table {target_ip}"
            elif 'xe' in device_type.lower():
                command = f"show ip route {target_ip}"
            elif 'xr' in device_type.lower():
                command = f"show route {target_ip}"
            else:
                msg = f"Tipo no reconocido: {device_type}"
                self.log_to_streamlit(msg, "warning")
                return device_ip, device_type, None, msg
            
            output, error = self.execute_command(ssh, command, device_ip)
            
            if error:
                return device_ip, device_type, None, error
            
            # Análisis detallado con logging
            if output:
                self.log_to_streamlit(f"Respuesta de {device_ip}:\n{output[:200]}...", "info")
                
                if 'huawei' in device_type.lower():
                    if f"{target_ip}/" in output or "Routing Table" in output:
                        self.log_to_streamlit(f"IP encontrada en Huawei {device_ip}", "success")
                        return device_ip, device_type, output, None
                elif 'xe' in device_type.lower():
                    if "is directly connected" in output or "is subnetted" in output or f" {target_ip} " in output:
                        self.log_to_streamlit(f"IP encontrada en IOS XE {device_ip}", "success")
                        return device_ip, device_type, output, None
                elif 'xr' in device_type.lower():
                    if f" {target_ip}/" in output or "Routing entry for" in output:
                        self.log_to_streamlit(f"IP encontrada en IOS XR {device_ip}", "success")
                        return device_ip, device_type, output, None
            
            self.log_to_streamlit(f"IP no encontrada en {device_ip}", "info")
            return device_ip, device_type, None, "IP no encontrada en la tabla de routing"
        except Exception as e:
            self.log_to_streamlit(f"Error procesando {device_ip}: {str(e)}", "warning")
            return device_ip, device_type, None, str(e)
        finally:
            if ssh:
                ssh.close()

    def process_devices(self, excel_data, target_ip):
        """Procesa todos los dispositivos en el archivo Excel"""
        try:
            df = pd.read_excel(BytesIO(excel_data))
            df['IP'] = df['IP'].astype(str).str.strip()
            df['Tipo'] = df['Tipo'].astype(str).str.strip().str.lower()
            devices = list(zip(df['IP'], df['Tipo']))
        except Exception as e:
            self.log_to_streamlit(f"Error al procesar Excel: {str(e)}", "error")
            return None
        
        self.log_to_streamlit(f"🔍 Iniciando búsqueda de {target_ip} en {len(devices)} dispositivos", "info")
        
        found_devices = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self.check_duplicate_ip, 
                    device_ip, 
                    device_type, 
                    target_ip
                ): (device_ip, device_type) 
                for device_ip, device_type in devices
            }
            
            for future in as_completed(futures):
                device_ip, device_type = futures[future]
                result_ip, result_type, output, error = future.result()
                
                if output:
                    found_devices.append((result_ip, result_type, output))
        
        elapsed_time = time.time() - start_time
        self.log_to_streamlit(f"⏱️ Tiempo total: {elapsed_time:.2f} segundos", "info")
        
        return found_devices

def main():
    st.set_page_config(page_title="Network IP Scanner with Logs", layout="wide")
    
    st.title("🌐 Network IP Scanner with Detailed Logs")
    st.markdown("""
    **Versión con sistema de logging completo** para diagnóstico de problemas
    """)
    
    # Sidebar
    with st.sidebar:
        st.header("🔐 Credenciales SSH")
        username = st.text_input("Usuario", "juribeb")
        password = st.text_input("Contraseña", type="password")
        
        st.markdown("---")
        st.header("📋 Configuración de Logs")
        log_level = st.selectbox("Nivel de Log", ["INFO", "DEBUG", "WARNING", "ERROR"])
        logging.getLogger().setLevel(log_level)
    
    # Área principal
    uploaded_file = st.file_uploader("Sube archivo Excel con dispositivos", type=['xlsx'])
    
    if uploaded_file is not None:
        target_ip = st.text_input("IP a buscar", "172.20.142.85")
        
        # Contenedor para logs
        log_container = st.container()
        log_container.header("📝 Logs de Ejecución")
        log_placeholder = log_container.empty()
        
        if st.button("🚀 Iniciar Escaneo con Logs Detallados"):
            # Limpiar logs anteriores
            log_placeholder.empty()
            
            # Redirigir logs al contenedor
            scanner = NetworkDeviceScanner(username, password)
            scanner.log_to_streamlit = lambda msg, level: log_placeholder.markdown(f"`{msg}`")
            
            # Ejecutar escaneo
            found_devices = scanner.process_devices(uploaded_file.read(), target_ip)
            
            # Mostrar resultados finales
            if found_devices:
                st.success(f"🎯 IP encontrada en {len(found_devices)} dispositivos:")
                for device_ip, device_type, _ in found_devices:
                    st.write(f"- {device_ip} ({device_type})")
            else:
                st.warning(f"La IP {target_ip} no se encontró en ningún dispositivo")

if __name__ == "__main__":
    main()
