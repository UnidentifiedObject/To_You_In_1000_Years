# ⏳ Python Time Capsule with Encryption

A desktop application built with **Python** and **Tkinter** that allows users to create and manage multiple digital time capsules. Each capsule stores a secret message that will only be revealed after a specified future date and time — secured with strong encryption.


## ✨ Features

- **Multiple Capsules**  
  Create and manage an unlimited number of distinct time capsules.

- **Encrypted Messages**  
  All secret messages are encrypted using `cryptography.fernet` (AES-128 in CBC mode with HMAC) derived from a user-provided password and a unique salt, ensuring data confidentiality.

- **Password-Protected Decryption**  
  Messages can only be decrypted by providing the correct password at the time of opening.

- **Persistent Data**  
  Capsule configurations (unlock time, encrypted message, salt) are saved to a local JSON file, so your capsules persist even if the application is closed.

- **Live Countdown**  
  A real-time countdown displays the remaining time until a selected capsule opens.

- **"Once it's Gone, It's Gone" Principle**  
  Once a capsule is created, its content and unlock time are fixed and cannot be edited. If changes are needed, the capsule must be deleted and recreated.

- **One-Time Reveal Option**  
  After a capsule opens and its message is decrypted, the user has the option to permanently delete the capsule's data — making it a true one-time reveal.

- **User-Friendly GUI**  
  An intuitive graphical interface built with **Tkinter** for easy interaction.

- **Input Validation**  
  Basic checks for valid date/time inputs and future unlock times.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.6+
- [`cryptography`] library

---


# ⏳ Şifreli Python Zaman Kapsülü

**Python** ve **Tkinter** kullanılarak geliştirilen bu masaüstü uygulaması, kullanıcıların birden fazla dijital zaman kapsülü oluşturmasına ve yönetmesine olanak tanır. Her kapsül, yalnızca belirlenen bir gelecek tarih ve saatte açılabilen gizli bir mesaj içerir — güçlü şifreleme ile korunur.



## ✨ Özellikler

- **Birden Fazla Kapsül**  
  Sınırsız sayıda farklı zaman kapsülü oluşturup yönetebilirsiniz.

- **Şifreli Mesajlar**  
  Tüm gizli mesajlar, kullanıcı tarafından sağlanan bir parola ve benzersiz bir salt kullanılarak türetilmiş `cryptography.fernet` (AES-128 CBC modu ve HMAC) ile şifrelenir. Bu sayede veri gizliliği sağlanır.

- **Parola ile Şifre Çözme**  
  Mesajlar yalnızca doğru parola girilerek açılabilir.

- **Kalıcı Veri Saklama**  
  Kapsül bilgileri (açılma zamanı, şifreli mesaj, salt) yerel bir JSON dosyasına kaydedilir. Uygulama kapatılsa bile kapsüller korunur.

- **Canlı Geri Sayım**  
  Seçilen kapsülün açılmasına kalan süre gerçek zamanlı olarak gösterilir.

- **"Gitti mi, Gitti" Prensibi**  
  Bir kapsül oluşturulduktan sonra, içeriği ve açılma zamanı değiştirilemez. Değişiklik yapılması gerekiyorsa, kapsül silinip yeniden oluşturulmalıdır.

- **Tek Seferlik Gösterim Seçeneği**  
  Bir kapsül açıldıktan ve mesaj çözüldükten sonra, kullanıcı kapsül verilerini kalıcı olarak silebilir — böylece gerçek bir tek seferlik görüntüleme sağlanır.

- **Kullanıcı Dostu Arayüz**  
  **Tkinter** ile oluşturulmuş sezgisel ve kolay kullanılabilir bir grafik arayüz.

- **Girdi Doğrulama**  
  Geçerli tarih/saat ve gelecek zaman kontrolleri yapılır.

---

## 🚀 Başlarken

### Gereksinimler

- Python 3.6 ve üzeri
- [`cryptography`] kütüphanesi  
 


