import streamlit as st
import paramiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
from io import BytesIO
import queue
from datetime import datetime

class NetworkDeviceScanner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.ssh_timeout = 25  # Aumentado significativamente
        self.command_timeout = 30
        self.max_workers = 5  # Reducido para conexiones más estables
        self.max_retries = 2  # Intentos de reconexión
        self.log_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.results_queue = queue.Queue()

    def log_message(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"
        self.log_queue.put((level, formatted_msg))

    def update_progress(self, current, total):
        self.progress_queue.put((current, total))

    def add_result(self, device_ip, device_type, output):
        self.results_queue.put(("found", device_ip, device_type, output))

    def connect_to_device(self, device_ip, device_type):
        """Conexión SSH con reintentos y manejo mejorado de errores"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        for attempt in range(self.max_retries + 1):
            try:
                self.log_message(f"Intento {attempt + 1} para {device_ip}...")
                ssh.connect(device_ip, 
                          username=self.username, 
                          password=self.password, 
                          timeout=self.ssh_timeout,
                          banner_timeout=60,  # Muy importante para Huawei
                          look_for_keys=False,
                          allow_agent=False)
                self.log_message(f"Conexión exitosa a {device_ip}", "success")
                return ssh
            except socket.timeout as e:
                if attempt == self.max_retries:
                    self.log_message(f"Timeout persistente en {device_ip} ({device_type}). Posibles causas:\n"
                                   f"1. Dispositivo sobrecargado\n"
                                   f"2. Problemas de red\n"
                                   f"3. ACL bloqueando conexiones", "error")
                    return None
                time.sleep(5)  # Espera antes de reintentar
            except Exception as e:
                self.log_message(f"Error en {device_ip} (intento {attempt + 1}): {str(e)}", "warning")
                if attempt == self.max_retries:
                    return None
                time.sleep(3)
        
        return None

    def execute_command(self, ssh, command, device_ip):
        """Ejecución de comandos con manejo robusto"""
        try:
            self.log_message(f"Ejecutando en {device_ip}: {command}")
            
            # Configurar canal con timeout extendido
            chan = ssh.get_transport().open_session()
            chan.settimeout(self.command_timeout)
            chan.exec_command(command)
            
            # Leer salida en chunks
            output = ""
            while True:
                data = chan.recv(4096).decode('utf-8', errors='ignore')
                if not data:
                    break
                output += data
            
            exit_status = chan.recv_exit_status()
            if exit_status != 0:
                self.log_message(f"Comando falló en {device_ip} (código {exit_status})", "warning")
                return None
                
            return output.strip()
        except Exception as e:
            self.log_message(f"Error ejecutando comando en {device_ip}: {str(e)}", "warning")
            return None

    def check_duplicate_ip(self, device_ip, device_type, target_ip):
        """Búsqueda mejorada con múltiples estrategias"""
        ssh = self.connect_to_device(device_ip, device_type)
        if not ssh:
            return False
        
        try:
            # Comandos alternativos para cada plataforma
            commands = []
            if 'huawei' in device_type.lower():
                commands = [
                    f"display ip routing-table {target_ip}",
                    f"display ip routing-table | include {target_ip}",
                    f"display current-configuration | include {target_ip}"
                ]
            elif 'xe' in device_type.lower():
                commands = [
                    f"show ip route {target_ip}",
                    f"show running-config | include {target_ip}"
                ]
            elif 'xr' in device_type.lower():
                commands = [
                    f"show route {target_ip}",
                    f"show running-config | include {target_ip}"
                ]
            
            # Probar múltiples comandos
            for cmd in commands:
                output = self.execute_command(ssh, cmd, device_ip)
                if output and self.analyze_output(output, target_ip, device_type):
                    self.add_result(device_ip, device_type, output)
                    return True
            
            self.log_message(f"IP no encontrada en {device_ip} después de {len(commands)} comandos", "info")
            return False
            
        except Exception as e:
            self.log_message(f"Error crítico en {device_ip}: {str(e)}", "error")
            return False
        finally:
            if ssh:
                ssh.close()

    def analyze_output(self, output, target_ip, device_type):
        """Análisis inteligente de la salida"""
        # Patrones comunes para todas las plataformas
        common_patterns = [
            f"{target_ip}/32",
            f" {target_ip} ",
            f"host {target_ip}",
            f"network {target_ip}"
        ]
        
        # Patrones específicos por plataforma
        if 'huawei' in device_type.lower():
            common_patterns.extend([
                f"Destination/Mask: {target_ip}",
                f"Routing entry for {target_ip}"
            ])
        elif 'xe' in device_type.lower():
            common_patterns.extend([
                f"is directly connected",
                f"is subnetted"
            ])
        elif 'xr' in device_type.lower():
            common_patterns.extend([
                f"Routing entry for {target_ip}",
                f"Known via"
            ])
        
        return any(pattern in output for pattern in common_patterns)

    def process_devices(self, excel_data, target_ip):
        try:
            df = pd.read_excel(BytesIO(excel_data))
            df['IP'] = df['IP'].astype(str).str.strip()
            df['Tipo'] = df['Tipo'].astype(str).str.strip().str.lower()
            
            # Filtrar IPs inválidas
            valid_devices = []
            for _, row in df.iterrows():
                try:
                    socket.inet_aton(row['IP'])
                    valid_devices.append((row['IP'], row['Tipo']))
                except socket.error:
                    self.log_message(f"IP inválida en el Excel: {row['IP']}", "error")
            
            devices = valid_devices
        except Exception as e:
            self.log_message(f"Error al procesar Excel: {str(e)}", "error")
            return False
        
        self.log_message(f"🔍 Iniciando búsqueda avanzada de {target_ip} en {len(devices)} dispositivos")
        
        start_time = time.time()
        total_devices = len(devices)
        found_count = 0
        
        # Estrategia: Procesar primero los dispositivos Huawei
        prioritized_devices = sorted(devices, key=lambda x: (0 if 'huawei' in x[1].lower() else 1))
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self.check_duplicate_ip, 
                    device_ip, 
                    device_type, 
                    target_ip
                ): (device_ip, device_type) 
                for device_ip, device_type in prioritized_devices
            }
            
            for i, future in enumerate(as_completed(futures), 1):
                device_ip, device_type = futures[future]
                self.update_progress(i, total_devices)
                if future.result():
                    found_count += 1
        
        elapsed_time = time.time() - start_time
        self.log_message(f"⏱ Búsqueda completada en {elapsed_time:.2f} segundos", "info")
        self.results_queue.put(("summary", found_count, total_devices, target_ip))
        
        return found_count > 0

def display_ui_updates(log_placeholder, progress_bar, progress_text, results_area, scanner):
    """Muestra actualizaciones en la UI desde el hilo principal"""
    while True:
        # Procesar logs
        while not scanner.log_queue.empty():
            level, message = scanner.log_queue.get()
            if level == "error":
                log_placeholder.error(f"❌ {message}")
            elif level == "warning":
                log_placeholder.warning(f"⚠️ {message}")
            elif level == "success":
                log_placeholder.success(f"✅ {message}")
            else:
                log_placeholder.info(f"ℹ️ {message}")
        
        # Procesar progreso
        while not scanner.progress_queue.empty():
            current, total = scanner.progress_queue.get()
            progress_bar.progress(current / total)
            progress_text.text(f"📶 Procesados: {current}/{total} | Pendientes: {total-current}")
        
        # Procesar resultados
        while not scanner.results_queue.empty():
            result_type, *data = scanner.results_queue.get()
            if result_type == "found":
                device_ip, device_type, output = data
                with results_area.expander(f"🎯 IP encontrada en {device_ip} ({device_type})", expanded=True):
                    st.text_area("Salida del comando:", 
                               value=output, 
                               height=300,
                               key=f"result_{device_ip}")
            elif result_type == "summary":
                found_count, total_devices, target_ip = data
                if found_count > 0:
                    results_area.success(f"🔍 RESUMEN: La IP {target_ip} se encontró en {found_count} dispositivo(s)")
                else:
                    results_area.error(f"🔍 RESUMEN: La IP {target_ip} NO se encontró en {total_devices} dispositivos. "
                                    f"Posibles causas:\n"
                                    f"1. La IP no está configurada\n"
                                    f"2. Problemas de conectividad\n"
                                    f"3. Comandos no compatibles")
        
        time.sleep(0.5)

def main():
    st.set_page_config(page_title="Buscador Profesional de IP", layout="wide")
    st.title("🛠️ Buscador Profesional de IP en Red")
    
    with st.sidebar:
        st.header("🔐 Credenciales SSH")
        username = st.text_input("Usuario", "juribeb", key="user_input")
        password = st.text_input("Contraseña", type="password", key="pass_input")
        
        st.markdown("---")
        st.warning("""
        **Solución para timeouts:**
        1. Aumentar tiempos de espera
        2. Verificar conectividad
        3. Reintentar conexiones fallidas
        """)
    
    uploaded_file = st.file_uploader("📂 Subir archivo Excel (columnas: IP, Tipo)", type=['xlsx'])
    
    if uploaded_file:
        target_ip = st.text_input("🔎 IP a buscar", "172.20.142.85", key="ip_input")
        
        if st.button("🚀 Ejecutar Búsqueda Profunda", use_container_width=True):
            # Validar formato de IP
            try:
                socket.inet_aton(target_ip)
            except socket.error:
                st.error("⚠️ Formato de IP inválido")
                return
            
            # Configurar UI
            progress_bar = st.progress(0)
            progress_text = st.empty()
            log_container = st.expander("📜 Logs Detallados", expanded=True)
            log_placeholder = log_container.empty()
            results_area = st.container()
            
            # Iniciar escaneo
            scanner = NetworkDeviceScanner(username, password)
            
            def run_scan():
                try:
                    scanner.process_devices(uploaded_file.read(), target_ip)
                except Exception as e:
                    log_placeholder.error(f"💥 Error crítico: {str(e)}")
            
            import threading
            scan_thread = threading.Thread(target=run_scan)
            scan_thread.start()
            
            # Mostrar actualizaciones
            while scan_thread.is_alive():
                display_ui_updates(log_placeholder, progress_bar, progress_text, results_area, scanner)
                time.sleep(0.5)
            
            # Procesar mensajes finales
            display_ui_updates(log_placeholder, progress_bar, progress_text, results_area, scanner)

if __name__ == "__main__":
    main()
