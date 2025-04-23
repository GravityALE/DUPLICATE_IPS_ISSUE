import streamlit as st
import paramiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
from io import BytesIO

class NetworkDeviceScanner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.ssh_timeout = 10
        self.command_timeout = 15
        self.max_workers = 15  # Reducido para mayor estabilidad

    def connect_to_device(self, device_ip, device_type):
        """Establece conexión SSH con el dispositivo"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(device_ip, 
                      username=self.username, 
                      password=self.password, 
                      timeout=self.ssh_timeout,
                      banner_timeout=30,
                      look_for_keys=False,
                      allow_agent=False)
            return ssh
        except socket.timeout:
            st.warning(f"Timeout al conectar a {device_ip} ({device_type})")
            return None
        except Exception as e:
            st.warning(f"Error al conectar a {device_ip} ({device_type}): {str(e)}")
            return None

    def execute_command(self, ssh, command):
        """Ejecuta un comando y devuelve la salida"""
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=self.command_timeout)
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            
            if error and "Invalid input detected" not in error:
                return None, error
            return output, None
        except Exception as e:
            return None, str(e)

    def check_duplicate_ip(self, device_ip, device_type, target_ip):
        """Verifica si la IP está en el dispositivo"""
        ssh = self.connect_to_device(device_ip, device_type)
        if not ssh:
            return device_ip, device_type, None, "Error de conexión"
        
        try:
            # Determinar el comando según el tipo de dispositivo
            if 'huawei' in device_type.lower():
                command = f"display ip routing-table {target_ip}"
            elif 'xe' in device_type.lower():
                command = f"show ip route {target_ip}"
            elif 'xr' in device_type.lower():
                command = f"show route {target_ip}"
            else:
                return device_ip, device_type, None, f"Tipo no reconocido: {device_type}"
            
            output, error = self.execute_command(ssh, command)
            
            if error:
                return device_ip, device_type, None, error
            
            # Analizar la salida para cada tipo de dispositivo
            if output:
                if 'huawei' in device_type.lower():
                    if f"{target_ip}/" in output or "Routing Table" in output:
                        return device_ip, device_type, output, None
                elif 'xe' in device_type.lower():
                    if "is directly connected" in output or "is subnetted" in output or f" {target_ip} " in output:
                        return device_ip, device_type, output, None
                elif 'xr' in device_type.lower():
                    if f" {target_ip}/" in output or "Routing entry for" in output:
                        return device_ip, device_type, output, None
            
            return device_ip, device_type, None, "IP no encontrada"
        except Exception as e:
            return device_ip, device_type, None, str(e)
        finally:
            if ssh:
                ssh.close()

    def process_devices(self, excel_data, target_ip, progress_bar, progress_text, status_text):
        """Procesa todos los dispositivos en el archivo Excel"""
        try:
            df = pd.read_excel(BytesIO(excel_data))
            
            # Validar y limpiar los datos
            df['IP'] = df['IP'].astype(str).str.strip()
            df['Tipo'] = df['Tipo'].astype(str).str.strip().str.lower()
            
            devices = list(zip(df['IP'], df['Tipo']))
        except Exception as e:
            st.error(f"Error al procesar el archivo Excel: {str(e)}")
            return None
        
        st.info(f"🔍 Buscando IP {target_ip} en {len(devices)} dispositivos...")
        
        found_devices = []
        start_time = time.time()
        total_devices = len(devices)
        processed_devices = 0
        
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
                processed_devices += 1
                progress = processed_devices / total_devices
                progress_bar.progress(progress)
                progress_text.text(f"📡 Procesados: {processed_devices}/{total_devices}")
                
                result_ip, result_type, output, error = future.result()
                
                if output:
                    status_text.markdown(f"✅ **Encontrado en {result_ip}** ({result_type})")
                    with st.expander(f"Detalles {result_ip}"):
                        st.code(output)
                    found_devices.append((result_ip, result_type, output))
                elif error:
                    status_text.markdown(f"⚠️ {device_ip} ({device_type}): {error}")
        
        elapsed_time = time.time() - start_time
        st.info(f"⏱️ Tiempo total: {elapsed_time:.2f} segundos")
        
        return found_devices

def validate_ip(ip):
    """Valida que la IP tenga formato correcto"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def main():
    st.set_page_config(page_title="Network IP Scanner", layout="wide")
    
    st.title("🌐 Network IP Scanner")
    st.markdown("""
    Herramienta para buscar direcciones IP en dispositivos de red mediante SSH.
    **Tipos soportados:** IOS XE, IOS XR, Huawei
    """)
    
    # Sidebar
    with st.sidebar:
        st.header("🔐 Credenciales SSH")
        username = st.text_input("Usuario", "juribeb")
        password = st.text_input("Contraseña", type="password")
        
        st.markdown("---")
        st.header("📋 Requisitos del Excel")
        st.info("""
        - Columna **'IP'**: Direcciones de los dispositivos
        - Columna **'Tipo'**: IOS XE, IOS XR o Huawei
        """)
    
    # Main content
    uploaded_file = st.file_uploader("Sube archivo Excel con dispositivos", type=['xlsx'])
    
    if uploaded_file is not None:
        target_ip = st.text_input("IP a buscar", "172.20.142.101")
        
        if st.button("🚀 Iniciar Escaneo", use_container_width=True) and target_ip:
            if not validate_ip(target_ip):
                st.error("Formato de IP inválido. Use formato: 192.168.1.1")
                return
            
            # UI elements for progress
            progress_bar = st.progress(0)
            progress_text = st.empty()
            status_text = st.empty()
            results_container = st.container()
            
            try:
                scanner = NetworkDeviceScanner(username, password)
                found_devices = scanner.process_devices(
                    uploaded_file.read(),
                    target_ip,
                    progress_bar,
                    progress_text,
                    status_text
                )
                
                # Show final results
                progress_text.empty()
                status_text.empty()
                
                with results_container:
                    if found_devices:
                        st.success(f"🎯 IP encontrada en {len(found_devices)} dispositivos:")
                        for idx, (device_ip, device_type, output) in enumerate(found_devices, 1):
                            st.markdown(f"**{idx}. {device_ip}** ({device_type})")
                    else:
                        st.warning(f"La IP {target_ip} no se encontró en ningún dispositivo")
            
            except Exception as e:
                st.error(f"Error durante el escaneo: {str(e)}")

if __name__ == "__main__":
    main()
