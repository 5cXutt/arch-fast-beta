#!/bin/bash

select_keyboard_layout() {
    echo "[+] Scegli un layout di tastiera:"
    find /usr/share/kbd/keymaps/ -type f -name "*.map.gz" | sed 's#.*/##' | sed 's/.map.gz//' | sort
    read scelto_layout
    
    if [ -f "/usr/share/kbd/keymaps/i386/qwerty/${scelto_layout}.map.gz" ]; then
        loadkeys $scelto_layout
        echo "[+] Layout di tastiera $scelto_layout caricato."
    else
        echo "[!] Errore: Layout di tastiera non trovato. Verifica l'input e riprova."
        exit 1
    fi
}
sync_system_clock() {
    echo "[+] Sincronizzazione dell'orologio di sistema..."
    timedatectl set-ntp true
    if timedatectl status | grep -q "NTP synchronized: yes"; then
        echo "[+] Orologio di sistema sincronizzato correttamente."
    else
        echo "[!] Errore durante la sincronizzazione dell'orologio di sistema."
        exit 1
    fi
}
partition_gpt() {
    echo -e "\n[+] Creazione delle partizioni GPT con supporto UEFI su $1..."
    
    parted --script $1 mklabel gpt || { echo "[!] Errore nella creazione della tabella GPT."; exit 1; }
    parted --script $1 mkpart ESP fat32 1MiB 1GiB || { echo "[!] Errore nella creazione della partizione EFI."; exit 1; }
    parted --script $1 set 1 esp on || { echo "[!] Errore nell'impostazione della partizione EFI."; exit 1; }
    parted --script $1 mkpart primary linux-swap 1GiB 5GiB || { echo "[!] Errore nella creazione della partizione swap."; exit 1; }
    parted --script $1 mkpart primary ext4 5GiB 100% || { echo "[!] Errore nella creazione della partizione root."; exit 1; }
    
    echo "[+] Partizionamento completato. Formattazione delle partizioni..."
    
    mkfs.fat -F32 ${1}1 || { echo "[!] Errore nella formattazione della partizione EFI."; exit 1; }
    mkswap ${1}2 || { echo "[!] Errore nella formattazione della partizione swap."; exit 1; }
    swapon ${1}2 || { echo "[!] Errore nell'attivazione della partizione swap."; exit 1; }
    mkfs.ext4 ${1}3 || { echo "[!] Errore nella formattazione della partizione root."; exit 1; }
    
    echo "[+] Formattazione completata."
}
partition_mbr() {
    echo -e "\n[+] Creazione delle partizioni MBR con supporto BIOS su $1..."
    
    parted --script $1 mklabel msdos || { echo "[!] Errore nella creazione della tabella MBR."; exit 1; }
    parted --script $1 mkpart primary linux-swap 1MiB 4GiB || { echo "[!] Errore nella creazione della partizione swap."; exit 1; }
    parted --script $1 mkpart primary ext4 4GiB 100% || { echo "[!] Errore nella creazione della partizione root."; exit 1; }
    
    echo "[+] Partizionamento completato. Formattazione delle partizioni..."
    
    mkswap ${1}1 || { echo "[!] Errore nella formattazione della partizione swap."; exit 1; }
    swapon ${1}1 || { echo "[!] Errore nell'attivazione della partizione swap."; exit 1; }
    mkfs.ext4 ${1}2 || { echo "[!] Errore nella formattazione della partizione root."; exit 1; }
    
    echo "[+] Formattazione completata."
}
select_disk() {
    echo "[+] Dispositivi disponibili per il partizionamento:"
    lsblk -e 7,11
    
    echo -e "\n[+] Inserisci il nome del dispositivo da partizionare (es. /dev/sda, /dev/nvme0n1, /dev/mmcblk0):"
    read device
    
    if [ ! -b "$device" ]; then
        echo "[!] Errore: il dispositivo $device non esiste. Controlla l'input e riprova."
        exit 1
    fi
}
partition_disk() {
    echo -e "\n[+] Il sistema utilizza UEFI? (s/n)"
    read uefi
    
    if [ "$uefi" == "s" ]; then
        partition_gpt $device
    else
        partition_mbr $device
    fi
}
install_base_system() {
    echo "[+] Installazione del sistema di base (pacchetti essenziali)..."
    pacstrap /mnt base linux linux-firmware || { echo "[!] Errore nell'installazione dei pacchetti di base."; exit 1; }
    echo "[+] Sistema di base installato."
}
generate_fstab() {
    echo "[+] Generazione del file fstab..."
    genfstab -U /mnt >> /mnt/etc/fstab || { echo "[!] Errore nella generazione del file fstab."; exit 1; }
    echo "[+] File fstab generato."
}
install_other_dependencies() {
    echo "[+] Installazione di altre dipendenze..."
    pacstrap /mnt nano nvim neofetch python3 lua || { echo "[!] Errore nell'installazione delle dipendenze."; exit 1; }
    echo "[+] Altre dipendenze installate."
}
configure_system() {
    arch-chroot /mnt /bin/bash <<EOF
        ln -sf /usr/share/zoneinfo/Europe/Rome /etc/localtime
        hwclock --systohc
        echo "[+] Fuso orario e orologio hardware configurati."

        echo "[+] Configurazione della localizzazione..."
        sed -i 's/^#en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
        locale-gen
        echo "LANG=en_US.UTF-8" > /etc/locale.conf
        echo "KEYMAP=it" > /etc/vconsole.conf
        echo "[+] Localizzazione configurata."

        echo "[+] Imposta la password di root:"
        passwd
EOF
    echo "[+] Configurazione del sistema completata."
}
install_arch_linux() {
    select_keyboard_layout
    sync_system_clock
    select_disk
    partition_disk
    mount ${device}3 /mnt
    install_base_system
    generate_fstab
    install_other_dependencies
    configure_system
    echo "[+] Installazione completata! Ora esci dall'ambiente chroot e riavvia il sistema."
}

install_arch_linux
