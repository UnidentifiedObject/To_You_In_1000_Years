import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, Listbox, END, ACTIVE
import datetime
import json
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode

# --- Configuration File ---
CONFIG_FILE = "capsule_config.json"


# --- Key Derivation Function ---
def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a Fernet key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # Recommended iteration count for PBKDF2
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    return key


# --- Function to save ALL capsules ---
def save_all_capsules(capsules_list):
    """Saves the list of all capsules to a JSON file."""
    serializable_capsules = []
    for capsule in capsules_list:
        # Convert datetime to ISO format string, bytes to base64 string
        serializable_capsules.append({
            "name": capsule["name"],
            "unlock_time": capsule["unlock_time"].isoformat(),
            "encrypted_message": capsule["encrypted_message"].decode(),
            "salt": urlsafe_b64encode(capsule["salt"]).decode()
        })
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(serializable_capsules, f, indent=4)  # Use indent for readability
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save capsules: {e}")
        return False


# --- Function to load ALL capsules ---
def load_all_capsules():
    """Loads the list of all capsules from a JSON file."""
    if not os.path.exists(CONFIG_FILE):
        return []  # Return empty list if no config file found

    try:
        with open(CONFIG_FILE, "r") as f:
            serializable_capsules = json.load(f)

        loaded_capsules = []
        for capsule_data in serializable_capsules:
            try:
                unlock_dt = datetime.datetime.fromisoformat(capsule_data["unlock_time"])
                encrypted_message = capsule_data["encrypted_message"].encode()
                salt = urlsafe_b64decode(capsule_data["salt"].encode())
                loaded_capsules.append({
                    "name": capsule_data["name"],
                    "unlock_time": unlock_dt,
                    "encrypted_message": encrypted_message,
                    "salt": salt
                })
            except (KeyError, ValueError, TypeError) as e:
                print(f"Skipping corrupted capsule entry: {capsule_data} - Error: {e}")
                messagebox.showwarning("Corrupted Capsule",
                                       f"One or more capsule entries in '{CONFIG_FILE}' are corrupted and will be skipped.")
        return loaded_capsules
    except json.JSONDecodeError:
        messagebox.showerror("Error", "Invalid configuration file format. File might be corrupted.")
        # Optionally, delete the corrupted file here: os.remove(CONFIG_FILE)
        return []
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load capsules: {e}")
        return []


# --- Main GUI Application Class ---
class TimeCapsuleApp:
    def __init__(self, master):
        self.master = master
        master.title("Time Capsule")
        master.geometry("800x750")  # Increased size for new elements
        master.resizable(False, False)

        self.all_capsules = []  # List to hold all capsule dictionaries
        self.current_capsule_index = None  # Index of the currently selected capsule
        self.countdown_job = None

        # --- GUI Elements MUST be created first ---
        self.create_widgets()

        # --- Then load existing configuration and populate listbox ---
        self.load_existing_capsules_into_gui()

        # --- Start countdown if a capsule is automatically selected ---
        if self.current_capsule_index is not None:
            self.start_countdown()

    def create_widgets(self):
        # Frame for capsule list and management buttons
        capsule_list_frame = tk.LabelFrame(self.master, text="Your Time Capsules", padx=10, pady=10)
        capsule_list_frame.pack(pady=10, padx=10, fill="x")

        self.capsule_listbox = Listbox(capsule_list_frame, height=6,
                                       exportselection=0)  # exportselection=0 allows other listboxes to be selected
        self.capsule_listbox.pack(side="left", fill="both", expand=True)
        self.capsule_listbox.bind("<<ListboxSelect>>", self.on_capsule_select)

        listbox_scrollbar = tk.Scrollbar(capsule_list_frame, orient="vertical", command=self.capsule_listbox.yview)
        listbox_scrollbar.pack(side="right", fill="y")
        self.capsule_listbox.config(yscrollcommand=listbox_scrollbar.set)

        button_frame = tk.Frame(capsule_list_frame)
        button_frame.pack(side="right", padx=10)

        self.new_capsule_button = tk.Button(button_frame, text="Add New Capsule", command=self.add_new_capsule)
        self.new_capsule_button.pack(pady=5, fill="x")

        # Removed the "Edit Selected Capsule" button as per new requirement
        # self.edit_capsule_button = tk.Button(button_frame, text="Edit Selected Capsule", command=self.edit_selected_capsule, state=tk.DISABLED)
        # self.edit_capsule_button.pack(pady=5, fill="x")

        self.delete_capsule_button = tk.Button(button_frame, text="Delete Selected Capsule",
                                               command=self.delete_selected_capsule, state=tk.DISABLED)
        self.delete_capsule_button.pack(pady=5, fill="x")

        # Frame for input fields (for selected/new capsule)
        input_frame = tk.LabelFrame(self.master, text="Capsule Details", padx=10, pady=10)
        input_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(input_frame, text="Capsule Name:").grid(row=0, column=0, sticky="w", pady=2)
        self.name_entry = tk.Entry(input_frame, width=30)
        self.name_entry.grid(row=0, column=1, sticky="ew", pady=2)

        tk.Label(input_frame, text="Unlock Year (YYYY):").grid(row=1, column=0, sticky="w", pady=2)
        self.year_entry = tk.Entry(input_frame, width=10)
        self.year_entry.grid(row=1, column=1, sticky="ew", pady=2)

        tk.Label(input_frame, text="Unlock Month (1-12):").grid(row=2, column=0, sticky="w", pady=2)
        self.month_entry = tk.Entry(input_frame, width=10)
        self.month_entry.grid(row=2, column=1, sticky="ew", pady=2)

        tk.Label(input_frame, text="Unlock Day (1-31):").grid(row=3, column=0, sticky="w", pady=2)
        self.day_entry = tk.Entry(input_frame, width=10)
        self.day_entry.grid(row=3, column=1, sticky="ew", pady=2)

        tk.Label(input_frame, text="Unlock Hour (0-23):").grid(row=4, column=0, sticky="w", pady=2)
        self.hour_entry = tk.Entry(input_frame, width=10)
        self.hour_entry.grid(row=4, column=1, sticky="ew", pady=2)

        tk.Label(input_frame, text="Unlock Minute (0-59):").grid(row=5, column=0, sticky="w", pady=2)
        self.minute_entry = tk.Entry(input_frame, width=10)
        self.minute_entry.grid(row=5, column=1, sticky="ew", pady=2)

        tk.Label(input_frame, text="Unlock Second (0-59):").grid(row=6, column=0, sticky="w", pady=2)
        self.second_entry = tk.Entry(input_frame, width=10)
        self.second_entry.grid(row=6, column=1, sticky="ew", pady=2)

        tk.Label(input_frame, text="Secret Message:").grid(row=7, column=0, sticky="nw", pady=5)
        self.message_text = scrolledtext.ScrolledText(input_frame, width=40, height=6, wrap=tk.WORD)
        self.message_text.grid(row=7, column=1, columnspan=2, sticky="ew", pady=5)

        self.set_button = tk.Button(input_frame, text="Create New Capsule", command=self.save_current_capsule)
        self.set_button.grid(row=8, column=0, columnspan=2, pady=10)

        # Frame for status display
        status_frame = tk.LabelFrame(self.master, text="Selected Capsule Status", padx=10, pady=10)
        status_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.status_label = tk.Label(status_frame, text="Select or create a capsule.", font=("Helvetica", 14),
                                     wraplength=750)
        self.status_label.pack(pady=10)

        self.message_display = scrolledtext.ScrolledText(status_frame, width=60, height=8, wrap=tk.WORD,
                                                         state="disabled")
        self.message_display.pack(pady=10, fill="both", expand=True)

        # Initially disable input fields until a new capsule is added or one is selected
        self.disable_input_fields()
        self.set_button.config(state=tk.DISABLED)  # Disable save button initially

    def load_existing_capsules_into_gui(self):
        """Loads all capsules from file and populates the listbox."""
        self.all_capsules = load_all_capsules()
        self.capsule_listbox.delete(0, END)  # Clear existing items

        if not self.all_capsules:
            self.status_label.config(text="No capsules found. Create a new one!")
            self.clear_input_fields()
            self.disable_input_fields()  # Keep disabled as no capsule is selected/being edited
            self.delete_capsule_button.config(state=tk.DISABLED)
            self.set_button.config(text="Create New Capsule",
                                   state=tk.DISABLED)  # Reset button for new capsule, but disabled
            return

        for capsule in self.all_capsules:
            self.capsule_listbox.insert(END, capsule["name"])

        # Automatically select the first capsule if available
        if self.all_capsules:
            self.capsule_listbox.selection_set(0)
            self.on_capsule_select(None)  # Manually call the selection handler

    def on_capsule_select(self, event):
        """Handles selection of a capsule from the listbox."""
        selected_indices = self.capsule_listbox.curselection()
        if not selected_indices:
            self.current_capsule_index = None
            self.clear_input_fields()
            self.disable_input_fields()  # Keep disabled if nothing selected
            self.status_label.config(text="Select or create a capsule.")
            self.message_display.config(state="normal")
            self.message_display.delete("1.0", END)
            self.message_display.config(state="disabled")
            self.delete_capsule_button.config(state=tk.DISABLED)
            self.set_button.config(text="Create New Capsule",
                                   state=tk.DISABLED)  # Reset button for new capsule, but disabled
            if self.countdown_job:
                self.master.after_cancel(self.countdown_job)
            return

        self.current_capsule_index = selected_indices[0]
        selected_capsule = self.all_capsules[self.current_capsule_index]

        self.disable_input_fields()  # Ensure fields are disabled as editing is not allowed
        self.set_button.config(text="Create New Capsule",
                               state=tk.DISABLED)  # Keep save button disabled for existing capsules
        self.delete_capsule_button.config(state=tk.NORMAL)

        # Populate input fields with selected capsule's data
        self.clear_input_fields()  # Clear first to avoid appending
        self.name_entry.config(state=tk.NORMAL)  # Temporarily enable to insert
        self.name_entry.insert(0, selected_capsule["name"])
        self.name_entry.config(state=tk.DISABLED)  # Disable again

        self.year_entry.config(state=tk.NORMAL)
        self.year_entry.insert(0, str(selected_capsule["unlock_time"].year))
        self.year_entry.config(state=tk.DISABLED)

        self.month_entry.config(state=tk.NORMAL)
        self.month_entry.insert(0, str(selected_capsule["unlock_time"].month))
        self.month_entry.config(state=tk.DISABLED)

        self.day_entry.config(state=tk.NORMAL)
        self.day_entry.insert(0, str(selected_capsule["unlock_time"].day))
        self.day_entry.config(state=tk.DISABLED)

        self.hour_entry.config(state=tk.NORMAL)
        self.hour_entry.insert(0, str(selected_capsule["unlock_time"].hour))
        self.hour_entry.config(state=tk.DISABLED)

        self.minute_entry.config(state=tk.NORMAL)
        self.minute_entry.insert(0, str(selected_capsule["unlock_time"].minute))
        self.minute_entry.config(state=tk.DISABLED)

        self.second_entry.config(state=tk.NORMAL)
        self.second_entry.insert(0, str(selected_capsule["unlock_time"].second))
        self.second_entry.config(state=tk.DISABLED)

        # We don't pre-fill the message_text with decrypted message for security/simplicity
        self.message_text.delete("1.0", END)  # Clear any previous message
        self.message_text.config(state=tk.DISABLED)  # Ensure message text is disabled

        # Start countdown for the selected capsule
        self.start_countdown()

    def clear_input_fields(self):
        """Clears all input entry and text fields."""
        self.name_entry.config(state=tk.NORMAL)  # Temporarily enable to clear
        self.name_entry.delete(0, END)
        self.name_entry.config(state=tk.DISABLED)

        self.year_entry.config(state=tk.NORMAL)
        self.year_entry.delete(0, END)
        self.year_entry.config(state=tk.DISABLED)

        self.month_entry.config(state=tk.NORMAL)
        self.month_entry.delete(0, END)
        self.month_entry.config(state=tk.DISABLED)

        self.day_entry.config(state=tk.NORMAL)
        self.day_entry.delete(0, END)
        self.day_entry.config(state=tk.DISABLED)

        self.hour_entry.config(state=tk.NORMAL)
        self.hour_entry.delete(0, END)
        self.hour_entry.config(state=tk.DISABLED)

        self.minute_entry.config(state=tk.NORMAL)
        self.minute_entry.delete(0, END)
        self.minute_entry.config(state=tk.DISABLED)

        self.second_entry.config(state=tk.NORMAL)
        self.second_entry.delete(0, END)
        self.second_entry.config(state=tk.DISABLED)

        self.message_text.config(state="normal")  # Temporarily enable to clear
        self.message_text.delete("1.0", END)
        self.message_text.config(state="disabled")

        self.message_display.config(state="normal")
        self.message_display.delete("1.0", END)
        self.message_display.config(state="disabled")

    def enable_input_fields(self):
        """Enables all input entry and text fields."""
        self.name_entry.config(state=tk.NORMAL)
        self.year_entry.config(state=tk.NORMAL)
        self.month_entry.config(state=tk.NORMAL)
        self.day_entry.config(state=tk.NORMAL)
        self.hour_entry.config(state=tk.NORMAL)
        self.minute_entry.config(state=tk.NORMAL)
        self.second_entry.config(state=tk.NORMAL)
        self.message_text.config(state=tk.NORMAL)
        self.set_button.config(state=tk.NORMAL)  # Enable save button when fields are enabled

    def disable_input_fields(self):
        """Disables all input entry and text fields."""
        self.name_entry.config(state=tk.DISABLED)
        self.year_entry.config(state=tk.DISABLED)
        self.month_entry.config(state=tk.DISABLED)
        self.day_entry.config(state=tk.DISABLED)
        self.hour_entry.config(state=tk.DISABLED)
        self.minute_entry.config(state=tk.DISABLED)
        self.second_entry.config(state=tk.DISABLED)
        self.message_text.config(state=tk.DISABLED)
        self.set_button.config(state=tk.DISABLED)  # Disable save button when fields are disabled

    def add_new_capsule(self):
        """Prepares the GUI for creating a new capsule."""
        self.capsule_listbox.selection_clear(0, END)  # Deselect any current item
        self.current_capsule_index = None
        self.clear_input_fields()
        self.enable_input_fields()  # Enable fields for new input
        self.set_button.config(text="Create New Capsule", state=tk.NORMAL)  # Enable and set text for new capsule
        self.status_label.config(text="Enter details for a new capsule.")
        # self.edit_capsule_button.config(state=tk.DISABLED) # Removed edit button
        self.delete_capsule_button.config(state=tk.DISABLED)
        if self.countdown_job:
            self.master.after_cancel(self.countdown_job)

    # Removed edit_selected_capsule method as per new requirement
    # def edit_selected_capsule(self):
    #     """Allows editing the currently selected capsule."""
    #     if self.current_capsule_index is None:
    #         messagebox.showwarning("No Capsule Selected", "Please select a capsule to edit.")
    #         return
    #     self.enable_input_fields()
    #     self.set_button.config(text="Update Capsule")
    #     messagebox.showinfo("Edit Capsule", "Edit the details in the 'Capsule Details' section and click 'Update Capsule'.")
    #     # The fields are already populated by on_capsule_select

    def delete_selected_capsule(self):
        """Deletes the currently selected capsule."""
        if self.current_capsule_index is None:
            messagebox.showwarning("No Capsule Selected", "Please select a capsule to delete.")
            return

        capsule_name = self.all_capsules[self.current_capsule_index]["name"]
        if messagebox.askyesno("Confirm Delete",
                               f"Are you sure you want to delete '{capsule_name}'? This cannot be undone."):
            del self.all_capsules[self.current_capsule_index]
            if save_all_capsules(self.all_capsules):
                messagebox.showinfo("Deleted", f"Capsule '{capsule_name}' deleted successfully.")
                self.load_existing_capsules_into_gui()  # Reload listbox
            else:
                messagebox.showerror("Error", "Failed to delete capsule.")

    def save_current_capsule(self):
        """Saves or updates the current capsule based on input fields."""
        try:
            capsule_name = self.name_entry.get().strip()
            year = int(self.year_entry.get())
            month = int(self.month_entry.get())
            day = int(self.day_entry.get())
            hour = int(self.hour_entry.get())
            minute = int(self.minute_entry.get())
            second = int(self.second_entry.get())
            message_to_encrypt = self.message_text.get("1.0", END).strip()

            if not capsule_name:
                messagebox.showerror("Invalid Input", "Capsule Name cannot be empty.")
                return

            # Check for duplicate names if adding a new capsule
            # This logic only applies when adding, not when 'updating' (which is now disabled)
            if self.current_capsule_index is None:  # This means we are creating a new capsule
                for capsule in self.all_capsules:
                    if capsule["name"].lower() == capsule_name.lower():
                        messagebox.showerror("Duplicate Name",
                                             f"A capsule named '{capsule_name}' already exists. Please choose a unique name.")
                        return

            new_unlock_dt = datetime.datetime(year, month, day, hour, minute, second)

            if new_unlock_dt <= datetime.datetime.now():
                messagebox.showerror("Invalid Time", "Unlock time must be in the future!")
                return

            if not message_to_encrypt:
                messagebox.showwarning("No Message", "You haven't entered a secret message! Capsule will be empty.")
                password = None  # No message, no password needed
            else:
                password = simpledialog.askstring("Password", "Enter a password to encrypt this message:", show='*')
                if not password:
                    messagebox.showerror("Encryption Error",
                                         "Password is required to encrypt the message. Capsule not saved.")
                    return

            new_salt = os.urandom(16)
            key = derive_key(password, new_salt)
            f = Fernet(key)
            encrypted_message = f.encrypt(message_to_encrypt.encode())

            new_capsule_data = {
                "name": capsule_name,
                "unlock_time": new_unlock_dt,
                "encrypted_message": encrypted_message,
                "salt": new_salt
            }

            # Since editing is disabled, this will always be adding a new capsule
            # The 'update' path is effectively removed by GUI state management
            self.all_capsules.append(new_capsule_data)
            action_msg = "created"

            if save_all_capsules(self.all_capsules):
                messagebox.showinfo("Success", f"Capsule '{capsule_name}' {action_msg} successfully!")
                self.load_existing_capsules_into_gui()  # Reload listbox to show changes

                # After saving, clear and disable inputs
                self.clear_input_fields()
                self.disable_input_fields()
                self.set_button.config(text="Create New Capsule",
                                       state=tk.DISABLED)  # Disable save button after creation
                self.delete_capsule_button.config(state=tk.DISABLED)  # Disable delete button if no capsule is selected

                # Select the newly created capsule
                for i, capsule in enumerate(self.all_capsules):
                    if capsule["name"] == capsule_name:
                        self.capsule_listbox.selection_set(i)
                        self.capsule_listbox.activate(i)
                        self.on_capsule_select(None)
                        break

            else:
                messagebox.showerror("Error", "Failed to save capsule.")

        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid numbers for date/time fields.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def start_countdown(self):
        """Starts or updates the countdown display for the selected capsule."""
        if self.countdown_job:
            self.master.after_cancel(self.countdown_job)

        self.update_countdown()

    def update_countdown(self):
        """Updates the countdown label every second for the selected capsule."""
        if self.current_capsule_index is None:
            self.status_label.config(text="Select or create a capsule.")
            return

        current_capsule = self.all_capsules[self.current_capsule_index]
        unlock_datetime = current_capsule["unlock_time"]
        current_datetime = datetime.datetime.now()

        if current_datetime >= unlock_datetime:
            self.open_time_capsule()
        else:
            time_remaining = unlock_datetime - current_datetime
            days = time_remaining.days
            seconds = int(time_remaining.total_seconds())
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            countdown_text = (
                f"Capsule '{current_capsule['name']}' will open on: {unlock_datetime.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"Time remaining: {days} days, {hours:02} hours, {minutes:02} minutes, {seconds:02} seconds"
            )
            self.status_label.config(text=countdown_text)
            self.countdown_job = self.master.after(1000, self.update_countdown)

    def open_time_capsule(self):
        """Reveals the hidden message by decrypting it and updates the GUI."""
        if self.countdown_job:
            self.master.after_cancel(self.countdown_job)

        if self.current_capsule_index is None:
            messagebox.showwarning("No Capsule Selected", "Please select a capsule to open.")
            return

        current_capsule = self.all_capsules[self.current_capsule_index]
        self.status_label.config(text=f"--- CAPSULE '{current_capsule['name']}' OPENED! ---",
                                 font=("Helvetica", 16, "bold"), fg="green")

        decrypted_message_content = "No encrypted message was set or decryption failed."  # Default message

        try:
            if current_capsule["encrypted_message"] and current_capsule["salt"]:
                password = simpledialog.askstring("Password Required",
                                                  f"Enter the password for '{current_capsule['name']}' to decrypt the message:",
                                                  show='*')
                if not password:
                    messagebox.showerror("Decryption Failed", "Password required to decrypt the message.")
                    return  # Exit if no password provided

                try:
                    key = derive_key(password, current_capsule["salt"])
                    f = Fernet(key)
                    decrypted_message_content = f.decrypt(current_capsule["encrypted_message"]).decode()
                    messagebox.showinfo("Time Capsule Opened!",
                                        f"Your secret message from '{current_capsule['name']}' has been revealed!")

                except InvalidToken:
                    messagebox.showerror("Decryption Failed",
                                         "Incorrect password or corrupted message. Cannot decrypt.")
                    decrypted_message_content = "Decryption failed. Incorrect password or corrupted data."
                except Exception as e:
                    messagebox.showerror("Decryption Error", f"An error occurred during decryption: {e}")
                    decrypted_message_content = f"An error occurred: {e}"
            else:
                messagebox.showinfo("No Message", "No encrypted message found in this capsule.")
        finally:
            self.message_display.config(state="normal")
            self.message_display.delete("1.0", END)
            self.message_display.insert(END, decrypted_message_content)
            self.message_display.config(state="disabled")

            # Optional: Clear the capsule data after opening
            if current_capsule["encrypted_message"] and messagebox.askyesno("Clear Capsule?",
                                                                            f"Do you want to clear '{current_capsule['name']}' data and password (making it a one-time reveal)?"):
                try:
                    self.delete_selected_capsule_without_confirm()  # Call helper to delete
                    messagebox.showinfo("Capsule Cleared", f"Capsule '{current_capsule['name']}' cleared.")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not clear capsule: {e}")

    def delete_selected_capsule_without_confirm(self):
        """Helper to delete the currently selected capsule without a confirmation dialog."""
        if self.current_capsule_index is not None:
            del self.all_capsules[self.current_capsule_index]
            save_all_capsules(self.all_capsules)
            self.load_existing_capsules_into_gui()  # Reload listbox


# --- Run the application ---
if __name__ == "__main__":
    root = tk.Tk()
    app = TimeCapsuleApp(root)
    root.mainloop()