import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.clock import Clock
from kivy.properties import StringProperty, BooleanProperty
from kivy.uix.widget import Widget
from kivy.uix.image import Image
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.gridlayout import GridLayout
from kivy.graphics import Color, RoundedRectangle, Rectangle
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from typing import Dict
import json
import requests
import os
import hashlib
import time

# Theme colors
BG_COLOR = (0.10, 0.07, 0.20, 1)      # #1a1333
ACCENT = (0.79, 0.51, 0.62, 1)        # #ca829f
HIGHLIGHT = (0.18, 0.11, 0.37, 1)     # #2f1c5f
TEXT = (1, 1, 1, 1)                   # #ffffff
SUCCESS = (0.3, 0.9, 0.5, 1)
ERROR = (1, 0.3, 0.3, 1)

DEFAULT_RPC = 'http://localhost:5000'

class Card(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        with self.canvas.before:
            Color(*HIGHLIGHT)
            self.bg = RoundedRectangle(radius=[16], pos=self.pos, size=self.size)
        self.bind(pos=self.update_bg, size=self.update_bg)
        self.padding = 16
        self.spacing = 12
    def update_bg(self, *args):
        self.bg.pos = self.pos
        self.bg.size = self.size

class ValidatorClient(BoxLayout):
    wallet_address = StringProperty('')
    balance = StringProperty('')
    validator_status = StringProperty('Not registered')
    rpc_url = StringProperty(DEFAULT_RPC)
    authority_file_loaded = BooleanProperty(False)
    mining_active = BooleanProperty(False)
    status_message = StringProperty('')
    
    # RPC Node's authority key (hardcoded for now as per discussion)
    # In a real app, this might be configurable or discovered.
    RPC_NODE_AUTHORITY_KEY = "lakha1p3c647x6ghhqfpz7f4qh4kmdgkm4a2agvc80f9"

    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.authority = None
        self.poll_event = None
        self.padding = 0
        self.spacing = 0
        self.build_ui()

    def build_ui(self):
        self.clear_widgets()
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*BG_COLOR)
            Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self.update_bg, size=self.update_bg)

        # Header bar
        header = BoxLayout(orientation='horizontal', size_hint=(1, 0.13), padding=[16, 16, 16, 8], spacing=12)
        logo = Widget(size_hint=(None, 1), width=48)
        header.add_widget(logo)
        header.add_widget(Label(text='[b]Lakha Validator Client[/b]', markup=True, font_size=28, color=ACCENT, halign='left', valign='middle'))
        self.add_widget(header)

        if not self.authority_file_loaded:
            self.build_login_view()
        else:
            self.build_main_view()

    def build_login_view(self):
        card = Card(orientation='vertical', size_hint=(0.98, 0.8), pos_hint={'center_x':0.5})
        card.add_widget(Label(text='[b]Import your authority file or wallet[/b]', markup=True, font_size=20, color=TEXT))
        # Manual file path input
        self.file_path_input = TextInput(hint_text='Enter file path...', multiline=False, size_hint=(1, 0.13), background_color=HIGHLIGHT, foreground_color=TEXT, cursor_color=ACCENT, padding=[10,10,10,10], font_size=16)
        card.add_widget(self.file_path_input)
        file_path_btn = Button(text='Load from Path', size_hint=(1, 0.13), background_color=ACCENT, color=TEXT, font_size=16, bold=True)
        file_path_btn.bind(on_release=lambda x: self.load_authority_file(self.file_path_input.text))
        card.add_widget(file_path_btn)
        # Mnemonic input
        self.mnemonic_input = TextInput(hint_text='Or enter mnemonic phrase...', multiline=True, size_hint=(1, 0.23), background_color=HIGHLIGHT, foreground_color=TEXT, cursor_color=ACCENT, padding=[10,10,10,10], font_size=16)
        card.add_widget(self.mnemonic_input)
        mnemonic_btn = Button(text='Import from Mnemonic', size_hint=(1, 0.13), background_color=ACCENT, color=TEXT, font_size=16, bold=True)
        mnemonic_btn.bind(on_release=lambda x: self.load_from_mnemonic(self.mnemonic_input.text))
        card.add_widget(mnemonic_btn)
        # Status message
        card.add_widget(self.status_label(self.status_message, error=True))
        self.add_widget(card)

    def build_main_view(self):
        tab_panel = TabbedPanel(do_default_tab=False, tab_pos='top_mid', background_color=BG_COLOR, tab_width=150)

        # Dashboard Tab
        dashboard_tab = TabbedPanelItem(text='Dashboard')
        dashboard_layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        wallet_card = Card(orientation='vertical', size_hint=(1, 1))
        wallet_card.add_widget(Label(text='[b]Wallet Address[/b]', markup=True, font_size=16, color=ACCENT))
        wallet_card.add_widget(Label(text=f'{self.wallet_address}', font_size=16, color=TEXT, halign='left'))
        wallet_card.add_widget(Label(text=f'Balance: [b]{self.balance} LAK[/b]', markup=True, font_size=18, color=SUCCESS if self.balance != 'N/A' else ERROR))
        wallet_card.add_widget(Label(text=f'Validator Status: [b]{self.validator_status}[/b]', markup=True, font_size=16, color=SUCCESS if self.validator_status == 'Registered' else ERROR))
        dashboard_layout.add_widget(wallet_card)
        dashboard_tab.add_widget(dashboard_layout)
        tab_panel.add_widget(dashboard_tab)

        # Validator Actions Tab
        actions_tab = TabbedPanelItem(text='Validator Actions')
        actions_layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        actions_card = Card(orientation='vertical', size_hint=(1, 1))
        actions_card.add_widget(Label(text='[b]Register as Validator[/b]', markup=True, font_size=16, color=ACCENT))
        stake_input = TextInput(hint_text='Stake Amount', multiline=False, size_hint=(1, 0.2), background_color=HIGHLIGHT, foreground_color=TEXT, cursor_color=ACCENT, padding=[10,10,10,10], font_size=16)
        actions_card.add_widget(stake_input)
        reg_btn = Button(text='Register as Validator', size_hint=(1, 0.2), background_color=ACCENT, color=TEXT, font_size=16, bold=True)
        reg_btn.bind(on_release=lambda x: self.register_validator(stake_input.text))
        actions_card.add_widget(reg_btn)
        actions_card.add_widget(Label(text='[b]Mining[/b]', markup=True, font_size=16, color=ACCENT))
        mine_btn = Button(text='Start Validator' if not self.mining_active else 'Stop Validator', size_hint=(1, 0.2), background_color=ACCENT, color=TEXT, font_size=16, bold=True)
        mine_btn.bind(on_release=self.toggle_mining)
        actions_card.add_widget(mine_btn)
        actions_layout.add_widget(actions_card)
        actions_tab.add_widget(actions_layout)
        tab_panel.add_widget(actions_tab)

        # Settings Tab
        settings_tab = TabbedPanelItem(text='Settings')
        settings_layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        settings_card = Card(orientation='vertical', size_hint=(1, 1))
        settings_card.add_widget(Label(text='[b]Node Settings[/b]', markup=True, font_size=16, color=ACCENT))
        rpc_input = TextInput(text=self.rpc_url, multiline=False, size_hint=(1, 0.2), background_color=HIGHLIGHT, foreground_color=TEXT, cursor_color=ACCENT, padding=[10,10,10,10], font_size=16)
        rpc_input.bind(on_text_validate=self.set_rpc_url)
        settings_card.add_widget(rpc_input)
        settings_layout.add_widget(settings_card)
        settings_tab.add_widget(settings_layout)
        tab_panel.add_widget(settings_tab)

        self.add_widget(tab_panel)
        self.add_widget(self.status_label(self.status_message, error=('error' in self.status_message.lower()), success=('mined' in self.status_message.lower() or 'submitted' in self.status_message.lower())))


    def update_bg(self, *args):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*BG_COLOR)
            Rectangle(pos=self.pos, size=self.size)

    def status_label(self, msg, error=False, success=False):
        if not msg:
            return Label(text='', size_hint_y=0.1)
        color = ERROR if error else (SUCCESS if success else ACCENT)
        return Label(text=msg, color=color, font_size=15, bold=True, size_hint=(1, 0.1))

    def _make_request(self, method: str, endpoint: str, data: Dict = None, headers: Dict = None) -> Dict:
        url = f'{self.rpc_url}{endpoint}'
        if headers is None:
            headers = {}
        try:
            if method.upper() == 'GET':
                r = requests.get(url, headers=headers, timeout=10)
            elif method.upper() == 'POST':
                r = requests.post(url, json=data, headers=headers, timeout=10)
            else:
                raise ValueError(f"Unsupported method: {method}")
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            self.status_message = f"API Request Error: {e}"
            self.build_ui()
            return {'status': 'error', 'message': str(e)}

    def load_authority_file(self, filepath):
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            self.authority = data
            self.wallet_address = data.get('address', '')
            self.authority_file_loaded = True
            self.status_message = 'Authority file loaded.'
            self.update_balance()
            self.check_validator_status()
            self.build_ui()
        except Exception as e:
            self.status_message = f'Failed to load authority file: {e}'
            self.build_ui()

    def load_from_mnemonic(self, mnemonic):
        try:
            r = self._make_request('POST', '/api/memoryvault/generate-from-mnemonic', payload)
            if r.get('status') == 'success':
                data = r['data']
                self.authority = data
                self.wallet_address = data.get('address', '')
                self.authority_file_loaded = True
                self.status_message = 'Wallet imported from mnemonic.'
                self.update_balance()
                self.check_validator_status()
                self.build_ui()
            else:
                self.status_message = f"Mnemonic import failed: {r.get('message', r.text)}"
                self.build_ui()
        except Exception as e:
            self.status_message = f'Mnemonic import error: {e}'
            self.build_ui()

    def set_rpc_url(self, instance):
        self.rpc_url = instance.text
        self.status_message = f'RPC endpoint set to {self.rpc_url}'
        self.build_ui()

    def update_balance(self):
        try:
            r = self._make_request('GET', f'/api/accounts/{self.wallet_address}/balance')
            if r.get('status') == 'success':
                self.balance = str(r['data']['balance'])
            else:
                self.balance = 'N/A'
        except Exception as e:
            self.balance = 'N/A'

    def check_validator_status(self):
        try:
            r = self._make_request('GET', f'/api/validators/{self.wallet_address}')
            if r.get('status') == 'success': # Assuming 200 means validator exists
                self.validator_status = 'Registered'
            else:
                self.validator_status = 'Not registered'
        except Exception as e:
            self.validator_status = 'Unknown'

    def register_validator(self, amount):
        try:
            if not amount.strip():
                self.status_message = "Please enter a stake amount."
                self.build_ui()
                return
            try:
                stake = float(amount)
                if stake <= 0:
                    self.status_message = "Stake amount must be positive."
                    self.build_ui()
                    return
            except ValueError:
                self.status_message = "Stake amount must be a number."
                self.build_ui()
                return

            payload = {
                'address': self.wallet_address,
                'stake_amount': stake
            }
            r = self._make_request('POST', '/api/validators', payload)
            
            if r.get('status') == 'success':
                self.status_message = 'Validator registration submitted!'
                self.check_validator_status()
            else:
                self.status_message = f"Registration failed: {r.get('message', 'Unknown error')}"
        except Exception as e:
            self.status_message = f'Registration error: {e}'
        self.build_ui()

    def toggle_mining(self, instance):
        if not self.mining_active:
            self.mining_active = True
            self.status_message = 'Validator started. Mining blocks...'
            self.build_ui()
            self.poll_event = Clock.schedule_interval(lambda dt: self.mine_block(), 5)
        else:
            self.mining_active = False
            self.status_message = 'Validator stopped.'
            self.build_ui()
            if self.poll_event:
                self.poll_event.cancel()

    def mine_block(self):
        try:
            # Generate message and signature
            message = str(time.time()) # Simple timestamp as message
            private_key = self.authority.get('private_key')
            if not private_key:
                self.status_message = "Error: Private key not found in loaded wallet."
                self.build_ui()
                return
            
            signature = hashlib.sha256((message + private_key).encode()).hexdigest()

            payload = {
                'address': self.wallet_address,
                'message': message,
                'signature': signature
            }
            r = self._make_request('POST', '/api/mining/mine', payload)
            
            if r.get('status') == 'success':
                self.status_message = f"Block mined! {r['data'].get('message', '')}"
                self.update_balance()
            elif r.get('status') == 'error' and 'No pending transactions' in r.get('message', ''):
                self.status_message = 'No pending transactions to mine.'
            else:
                self.status_message = f"Mining error: {r.get('message', 'Unknown error')}"
        except Exception as e:
            self.status_message = f'Mining error: {e}'
        self.build_ui()

class ValidatorApp(App):
    def build(self):
        return ValidatorClient()

if __name__ == '__main__':
    ValidatorApp().run()