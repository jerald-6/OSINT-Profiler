#!/usr/bin/env python3
"""
OSINT Profiler v1.0 - OSINT Investigation Tool
"""

import os
import re
import sys
import json
import time
import glob
import math
import hashlib
import random
import logging
import traceback
import requests
import concurrent.futures
import pytz
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from collections import Counter
from io import BytesIO
from html import unescape
import ctypes


logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('osint_profiler.log', encoding='utf-8')]
)
logger = logging.getLogger(__name__)


# Phonenumbers will be lazy-loaded inside extract_phone_intelligence
PHONENUMBERS_AVAILABLE = True # Assume true globally until extraction proves otherwise


try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except Exception:
    BeautifulSoup = None
    BEAUTIFULSOUP_AVAILABLE = False


from scrapling import Fetcher, StealthyFetcher
from lxml import html


try:
    from reportlab.lib.pagesizes import A4, LETTER, LEGAL
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, Image as RLImage)
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    REPORTLAB = True
except Exception:
    REPORTLAB = False


try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    Image = None
    PIL_AVAILABLE = False


try:
    from PyQt6 import QtWidgets
    from PyQt6.QtCore import pyqtSignal, QThread, QUrl, QByteArray, Qt
    from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                                 QLineEdit, QPushButton, QProgressBar, QTableWidget, QTableWidgetItem,
                                 QMessageBox, QFileDialog, QSpinBox, QTextEdit, QTabWidget, QGroupBox,
                                 QFormLayout, QDialog, QDialogButtonBox, QCheckBox, QButtonGroup, QComboBox,
                                 QStatusBar, QRadioButton, QProgressDialog, QAbstractItemView, QHeaderView,
                                 QMenu, QMenuBar, QSizePolicy, QTabBar)
    from PyQt6.QtGui import QDesktopServices, QFont, QFontDatabase, QPixmap, QIcon, QAction, QPainter, QColor, QPen
    PYQT6_AVAILABLE = True
except Exception:
    PYQT6_AVAILABLE = False


logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('osint_profiler.log', encoding='utf-8')]
)
logger = logging.getLogger(__name__)


def create_app_icon(size=64, dark_mode=True):
    if not PYQT6_AVAILABLE:
        return None
    pix = QPixmap(size, size)
    pix.fill(QColor('#2b2b2b' if dark_mode else '#ffffff'))
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    rect_color = QColor('#5aa0ff') if not dark_mode else QColor('#3b7dd8')
    p.setBrush(rect_color)
    p.setPen(Qt.PenStyle.NoPen)
    margin = int(size * 0.08)
    p.drawRoundedRect(margin, margin, size-2*margin, size-2*margin, 8, 8)
    font = QFont()
    font.setBold(True)
    font.setPointSize(int(size * 0.42))
    p.setFont(font)
    p.setPen(QColor('#ffffff'))
    p.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, "O")
    p.end()
    return QIcon(pix)

DEFAULT_CONFIG = {
    'max_workers': 6,
    'delay_min': 0.4,
    'delay_max': 1.2,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (compatible; OSINTProfiler/1.0; +https://github.com/)'
    ],
    'timeout': 12,
    'rate_limit': 1.0,
    'platforms': {
        'instagram': ['https://www.instagram.com/{}'],
        'twitter': ['https://twitter.com/{}', 'https://x.com/{}'],
        'github': ['https://github.com/{}'],
        'reddit': ['https://www.reddit.com/user/{}', 'https://reddit.com/user/{}'],
        'linkedin': ['https://www.linkedin.com/in/{}'],
        'youtube': ['https://www.youtube.com/@{}', 'https://www.youtube.com/channel/{}'],
        'facebook': ['https://www.facebook.com/{}'],
        'tiktok': ['https://www.tiktok.com/@{}'],
        'medium': ['https://medium.com/@{}'],
        'pinterest': ['https://www.pinterest.com/{}/'],
        'twitch': ['https://twitch.tv/{}'],
    },
    'social_domains': [
        'instagram.com', 'facebook.com', 'twitter.com', 'x.com',
        'github.com', 'linkedin.com', 'youtube.com', 'tiktok.com',
        'reddit.com', 'pinterest.com', 'twitch.tv', 'medium.com'
    ],
    'noise_domains': [
        'nomernoi.ru', 'vam-xvonili.com', 'ktozvonil.pro',
        'partsauto360.com', 'welldoneparts.com', 'autozparts.eu', 'mas-informacion.com'
    ]
}


DEFAULT_REPORT_CONFIG = {
    'timezone': 'Local',
    'sections': ['summary', 'findings', 'anomalies', 'statistics'],
    'font_family': 'Helvetica',
    'font_size': 10,
    'title_font_size': 16,
    'heading_font_size': 14,
    'page_size': 'A4',
    'show_confidence_colors': True,
    'include_previews': True,
    'group_by_confidence': False,
    'max_preview_length': 300,
    'logo_path': None,
    'watermark': None,
    'report_title': 'OSINT Investigation Report',
    'company_name': 'OSINT Profiler',
    'show_footer': True,
    'show_header': True,
    'compress_pdf': False,
    'quality': 'standard'
}


TIME_ZONES = [
    ('Local', 'Local System Time'),
    ('UTC', 'UTC'),
    ('GMT', 'GMT'),
    ('US/Eastern', 'Eastern Time'),
    ('US/Central', 'Central Time'),
    ('US/Mountain', 'Mountain Time'),
    ('US/Pacific', 'Pacific Time'),
    ('Europe/London', 'British Time'),
    ('Europe/Paris', 'Central European Time'),
    ('Asia/Kolkata', 'Indian Standard Time'),
    ('Asia/Tokyo', 'Japan Standard Time'),
    ('Australia/Sydney', 'Australian Eastern Time'),
]


COUNTRY_CODES = [
    ('', 'Auto-detect'),
    ('1', '+1 (USA/Canada)'),
    ('7', '+7 (Russia)'),
    ('20', '+20 (Egypt)'),
    ('27', '+27 (South Africa)'),
    ('30', '+30 (Greece)'),
    ('31', '+31 (Netherlands)'),
    ('32', '+32 (Belgium)'),
    ('33', '+33 (France)'),
    ('34', '+34 (Spain)'),
    ('36', '+36 (Hungary)'),
    ('39', '+39 (Italy)'),
    ('40', '+40 (Romania)'),
    ('41', '+41 (Switzerland)'),
    ('43', '+43 (Austria)'),
    ('44', '+44 (UK)'),
    ('45', '+45 (Denmark)'),
    ('46', '+46 (Sweden)'),
    ('47', '+47 (Norway)'),
    ('48', '+48 (Poland)'),
    ('49', '+49 (Germany)'),
    ('51', '+51 (Peru)'),
    ('52', '+52 (Mexico)'),
    ('53', '+53 (Cuba)'),
    ('54', '+54 (Argentina)'),
    ('55', '+55 (Brazil)'),
    ('56', '+56 (Chile)'),
    ('57', '+57 (Colombia)'),
    ('58', '+58 (Venezuela)'),
    ('60', '+60 (Malaysia)'),
    ('61', '+61 (Australia)'),
    ('62', '+62 (Indonesia)'),
    ('63', '+63 (Philippines)'),
    ('64', '+64 (New Zealand)'),
    ('65', '+65 (Singapore)'),
    ('66', '+66 (Thailand)'),
    ('81', '+81 (Japan)'),
    ('82', '+82 (South Korea)'),
    ('84', '+84 (Vietnam)'),
    ('86', '+86 (China)'),
    ('90', '+90 (Turkey)'),
    ('91', '+91 (India)'),
    ('92', '+92 (Pakistan)'),
    ('93', '+93 (Afghanistan)'),
    ('94', '+94 (Sri Lanka)'),
    ('95', '+95 (Myanmar)'),
    ('98', '+98 (Iran)'),
    ('212', '+212 (Morocco)'),
    ('213', '+213 (Algeria)'),
    ('216', '+216 (Tunisia)'),
    ('218', '+218 (Libya)'),
    ('220', '+220 (Gambia)'),
    ('221', '+221 (Senegal)'),
    ('222', '+222 (Mauritania)'),
    ('223', '+223 (Mali)'),
    ('224', '+224 (Guinea)'),
    ('225', '+225 (Ivory Coast)'),
    ('226', '+226 (Burkina Faso)'),
    ('227', '+227 (Niger)'),
    ('228', '+228 (Togo)'),
    ('229', '+229 (Benin)'),
    ('230', '+230 (Mauritius)'),
    ('231', '+231 (Liberia)'),
    ('232', '+232 (Sierra Leone)'),
    ('233', '+233 (Ghana)'),
    ('234', '+234 (Nigeria)'),
    ('235', '+235 (Chad)'),
    ('236', '+236 (Central African Republic)'),
    ('237', '+237 (Cameroon)'),
    ('238', '+238 (Cape Verde)'),
    ('239', '+239 (Sao Tome)'),
    ('240', '+240 (Equatorial Guinea)'),
    ('241', '+241 (Gabon)'),
    ('242', '+242 (Republic of Congo)'),
    ('243', '+243 (DR Congo)'),
    ('244', '+244 (Angola)'),
    ('245', '+245 (Guinea-Bissau)'),
    ('246', '+246 (British Indian Ocean Territory)'),
    ('248', '+248 (Seychelles)'),
    ('249', '+249 (Sudan)'),
    ('250', '+250 (Rwanda)'),
    ('251', '+251 (Ethiopia)'),
    ('252', '+252 (Somalia)'),
    ('253', '+253 (Djibouti)'),
    ('254', '+254 (Kenya)'),
    ('255', '+255 (Tanzania)'),
    ('256', '+256 (Uganda)'),
    ('257', '+257 (Burundi)'),
    ('258', '+258 (Mozambique)'),
    ('260', '+260 (Zambia)'),
    ('261', '+261 (Madagascar)'),
    ('262', '+262 (Reunion)'),
    ('263', '+263 (Zimbabwe)'),
    ('264', '+264 (Namibia)'),
    ('265', '+265 (Malawi)'),
    ('266', '+266 (Lesotho)'),
    ('267', '+267 (Botswana)'),
    ('268', '+268 (Eswatini)'),
    ('269', '+269 (Comoros)'),
    ('350', '+350 (Gibraltar)'),
    ('351', '+351 (Portugal)'),
    ('352', '+352 (Luxembourg)'),
    ('353', '+353 (Ireland)'),
    ('354', '+354 (Iceland)'),
    ('355', '+355 (Albania)'),
    ('356', '+356 (Malta)'),
    ('357', '+357 (Cyprus)'),
    ('358', '+358 (Finland)'),
    ('359', '+359 (Bulgaria)'),
    ('370', '+370 (Lithuania)'),
    ('371', '+371 (Latvia)'),
    ('372', '+372 (Estonia)'),
    ('373', '+373 (Moldova)'),
    ('374', '+374 (Armenia)'),
    ('375', '+375 (Belarus)'),
    ('376', '+376 (Andorra)'),
    ('377', '+377 (Monaco)'),
    ('378', '+378 (San Marino)'),
    ('380', '+380 (Ukraine)'),
    ('381', '+381 (Serbia)'),
    ('382', '+382 (Montenegro)'),
    ('383', '+383 (Kosovo)'),
    ('385', '+385 (Croatia)'),
    ('386', '+386 (Slovenia)'),
    ('387', '+387 (Bosnia)'),
    ('389', '+389 (North Macedonia)'),
    ('420', '+420 (Czech Republic)'),
    ('421', '+421 (Slovakia)'),
    ('423', '+423 (Liechtenstein)'),
    ('500', '+500 (Falkland Islands)'),
    ('501', '+501 (Belize)'),
    ('502', '+502 (Guatemala)'),
    ('503', '+503 (El Salvador)'),
    ('504', '+504 (Honduras)'),
    ('505', '+505 (Nicaragua)'),
    ('506', '+506 (Costa Rica)'),
    ('507', '+507 (Panama)'),
    ('508', '+508 (Saint Pierre)'),
    ('509', '+509 (Haiti)'),
    ('590', '+590 (Guadeloupe)'),
    ('591', '+591 (Bolivia)'),
    ('592', '+592 (Guyana)'),
    ('593', '+593 (Ecuador)'),
    ('594', '+594 (French Guiana)'),
    ('595', '+595 (Paraguay)'),
    ('596', '+596 (Martinique)'),
    ('597', '+597 (Suriname)'),
    ('598', '+598 (Uruguay)'),
    ('599', '+599 (Netherlands Antilles)'),
    ('670', '+670 (East Timor)'),
    ('672', '+672 (Antarctica)'),
    ('673', '+673 (Brunei)'),
    ('674', '+674 (Nauru)'),
    ('675', '+675 (Papua New Guinea)'),
    ('676', '+676 (Tonga)'),
    ('677', '+677 (Solomon Islands)'),
    ('678', '+678 (Vanuatu)'),
    ('679', '+679 (Fiji)'),
    ('680', '+680 (Palau)'),
    ('681', '+681 (Wallis and Futuna)'),
    ('682', '+682 (Cook Islands)'),
    ('683', '+683 (Niue)'),
    ('685', '+685 (Samoa)'),
    ('686', '+686 (Kiribati)'),
    ('687', '+687 (New Caledonia)'),
    ('688', '+688 (Tuvalu)'),
    ('689', '+689 (French Polynesia)'),
    ('690', '+690 (Tokelau)'),
    ('691', '+691 (Micronesia)'),
    ('692', '+692 (Marshall Islands)'),
    ('850', '+850 (North Korea)'),
    ('852', '+852 (Hong Kong)'),
    ('853', '+853 (Macau)'),
    ('855', '+855 (Cambodia)'),
    ('856', '+856 (Laos)'),
    ('880', '+880 (Bangladesh)'),
    ('886', '+886 (Taiwan)'),
    ('960', '+960 (Maldives)'),
    ('961', '+961 (Lebanon)'),
    ('962', '+962 (Jordan)'),
    ('963', '+963 (Syria)'),
    ('964', '+964 (Iraq)'),
    ('965', '+965 (Kuwait)'),
    ('966', '+966 (Saudi Arabia)'),
    ('967', '+967 (Yemen)'),
    ('968', '+968 (Oman)'),
    ('970', '+970 (Palestine)'),
    ('971', '+971 (UAE)'),
    ('972', '+972 (Israel)'),
    ('973', '+973 (Bahrain)'),
    ('974', '+974 (Qatar)'),
    ('975', '+975 (Bhutan)'),
    ('976', '+976 (Mongolia)'),
    ('977', '+977 (Nepal)'),
    ('992', '+992 (Tajikistan)'),
    ('993', '+993 (Turkmenistan)'),
    ('994', '+994 (Azerbaijan)'),
    ('995', '+995 (Georgia)'),
    ('996', '+996 (Kyrgyzstan)'),
    ('998', '+998 (Uzbekistan)'),
]


PAGE_SIZES = [
    ('A4', 'A4 (210x297mm)'),
    ('Letter', 'Letter (8.5x11in)'),
    ('Legal', 'Legal (8.5x14in)'),
]


REPORT_SECTIONS = [
    ('summary', 'Executive Summary'),
    ('findings', 'Detailed Findings'),
    ('anomalies', 'Anomaly Detection'),
    ('statistics', 'Statistics'),
    ('methodology', 'Methodology'),
    ('recommendations', 'Recommendations'),
    ('disclaimer', 'Disclaimer'),
]


UI_VISIBLE_SECTIONS = [
    ('summary', 'Executive Summary'),
    ('findings', 'Detailed Findings'),
    ('anomalies', 'Anomaly Detection'),
    ('statistics', 'Statistics'),
]


QUALITY_LEVELS = [
    ('draft', 'Draft (Fastest)'),
    ('standard', 'Standard'),
    ('high', 'High Quality'),
]


def extract_phone_intelligence(phone_str, country_code=None):
    global PHONENUMBERS_AVAILABLE
    try:
        import phonenumbers
        from phonenumbers import geocoder
        from phonenumbers import carrier
        from phonenumbers import timezone as phone_tz
    except ImportError:
        PHONENUMBERS_AVAILABLE = False
        return {
            'error': 'phonenumbers library not installed',
            'raw_input': phone_str,
            'message': 'Install with: pip install phonenumbers'
        }
    
    try:

        phone_clean = re.sub(r'[^\d+]', '', phone_str)
        

        if country_code and not phone_clean.startswith('+'):
            phone_clean = f'+{country_code}{phone_clean}'
        

        try:
            parsed = phonenumbers.parse(phone_clean, None)
        except:

            parsed = phonenumbers.parse(phone_clean)
        

        intelligence = {
            'raw_input': phone_str,
            'e164_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            'international_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'national_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            'country_code': f'+{parsed.country_code}',
            'country': geocoder.description_for_number(parsed, 'en'),
            'region': geocoder.description_for_number(parsed, 'en'),
            'carrier': carrier.name_for_number(parsed, 'en') or 'Unknown',
            'timezone': phone_tz.time_zones_for_number(parsed),
            'valid': phonenumbers.is_valid_number(parsed),
            'possible': phonenumbers.is_possible_number(parsed),
        }
        

        number_type = phonenumbers.number_type(parsed)
        type_mapping = {
            0: 'FIXED_LINE',
            1: 'MOBILE',
            2: 'FIXED_LINE_OR_MOBILE',
            3: 'TOLL_FREE',
            4: 'PREMIUM_RATE',
            5: 'SHARED_COST',
            6: 'VOIP',
            7: 'PERSONAL_NUMBER',
            8: 'PAGER',
            9: 'UAN',
            10: 'VOICEMAIL',
            27: 'UNKNOWN'
        }
        intelligence['line_type'] = type_mapping.get(number_type, 'UNKNOWN')
        
        return intelligence
        
    except Exception as e:
        logger.error(f"Phone intelligence extraction failed: {e}")
        return {
            'error': str(e),
            'raw_input': phone_str,
            'message': 'Failed to parse phone number'
        }


def check_spam_databases(phone):
    spam_reports = []
    cleaned = re.sub(r'\D', '', phone)
    
    if len(cleaned) < 10:
        return spam_reports
    
    spam_queries = [
        f'"{cleaned}" spam OR scam OR fraud OR "who called"',
        f'"{cleaned}" site:whocallsme.com OR site:800notes.com',
        f'"{cleaned}" site:tellows.com OR site:shouldianswer.com',
        f'"{cleaned}" "spam caller" OR "robocall" OR "telemarketer"',
    ]
    
    for query in spam_queries:
        spam_reports.append({
            'type': 'spam_check',
            'query': query,
            'source': 'public_databases',
            'confidence': 50,
            'timestamp': now_ts()
        })
    
    return spam_reports


def now_ts(timezone_str='UTC'):
    try:
        tz = pytz.timezone(timezone_str)
        return datetime.now(tz).isoformat()
    except:
        return datetime.now(timezone.utc).isoformat()

def format_timestamp(iso_ts, timezone_str='UTC', show_local=True):
    if not iso_ts:
        return ''
    try:
        dt = datetime.fromisoformat(str(iso_ts).replace('Z','+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        try:
            if timezone_str == 'Local':

                localized_dt = dt.astimezone()
                localized_str = localized_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
            else:
                target_tz = pytz.timezone(timezone_str)
                localized_dt = dt.astimezone(target_tz)
                localized_str = localized_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        except:
            localized_dt = dt.astimezone(timezone.utc)
            localized_str = localized_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        
        if show_local and timezone_str != 'Local':
            local = dt.astimezone()
            local_str = local.strftime('%Y-%m-%d %H:%M:%S %Z')
            return f"{localized_str} (Local: {local_str})"
        return localized_str
    except Exception:
        return str(iso_ts)


def sanitize_filename(name: str) -> str:
    if not name:
        return 'unknown'
    name = name.strip()
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    name = re.sub(r'\s+', '_', name)
    return name[:200]

def build_report_basename(email=None, phone=None, username=None):

    parts = []
    if email:
        email_safe = sanitize_filename(email)
        parts.append(email_safe)
    if phone:
        phone_clean = re.sub(r'\D', '', phone)
        phone_safe = sanitize_filename(phone_clean)
        parts.append(f"phone_{phone_safe}")
    if username:
        username_safe = sanitize_filename(username)
        parts.append(f"user_{username_safe}")
    if not parts:
        return "osint_unknown"
    return "osint_" + "_".join(parts)


def clean_text(text):

    if not text:
        return ""

    text = re.sub(r'[█■▪▫▬▭▮▯▰▱▲△▴▵▶▷▸▹►▻▼▽▾▿◀◁◂◃◄◅◆◇◈◉◊○◌◍◎●◐◑◒◓◔◕◖◗◘◙◚◛◜◝◞◟◠◡◢◣◤◥◦◧◨◩◪◫◬◭◮◯]', '', str(text))

    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_snippet(html_text, max_length=300):
    if not BEAUTIFULSOUP_AVAILABLE or not html_text:
        return ''
    try:
        soup = BeautifulSoup(html_text, 'html.parser')
        for s in soup(['script','style','noscript','header','footer','svg']):
            s.decompose()
        meta = soup.find('meta', attrs={'name':'description'}) or soup.find('meta', attrs={'property':'og:description'}) or soup.find('meta', attrs={'name':'twitter:description'})
        if meta and meta.get('content'):
            return clean_text(meta['content'][:max_length])
        title = soup.title.string.strip() if soup.title and soup.title.string else ''
        p = ''
        for tag in soup.find_all('p'):
            t = tag.get_text(separator=' ', strip=True)
            if t and len(t.split()) > 6:
                p = t
                break
        if title and p:
            return clean_text((title + ' - ' + p)[:max_length])
        text = soup.get_text(separator=' ', strip=True)
        return clean_text(text[:max_length])
    except Exception as e:
        logger.debug(f"extract_snippet error: {e}")
        return ''


def ddg_search(query, max_results=30):
    if _DDGS_pkg is not None:
        try:
            ddgs = _DDGS_pkg()
            try:
                res = list(ddgs.text(query, max_results=max_results))
                return res[:max_results]
            finally:
                try:
                    ddgs.close()
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"ddgs error: {e}")
    if _DDGS_cls is not None:
        try:
            with _DDGS_cls() as ddgs:
                res = list(ddgs.text(query, max_results=max_results))
                return res[:max_results]
        except Exception:
            pass

def ddg_search(query, max_results=30, proxy=None):
    try:
        fetcher = StealthyFetcher(proxy=proxy) if proxy else StealthyFetcher()
        page = fetcher.fetch(f'https://html.duckduckgo.com/html/?q={query}', headless=True)
        
        results = []
        for result in page.css('.result'):
            title = result.css('.result__title a::text').get()
            if not title: continue
            
            url = result.css('.result__url::attr(href)').get()
            
            if url and 'y.js' in url:
                continue

            if url and 'uddg=' in url:
                import urllib.parse
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                if 'uddg' in params:
                    url = params['uddg'][0]

            snippet = result.css('.result__snippet::text').get()
            
            results.append({
                'title': clean_text(title),
                'url': url,
                'snippet': clean_text(snippet)
            })
            if len(results) >= max_results:
                break
                
        return results
    except Exception as e:
        logger.warning(f"DuckDuckGo search failed: {e}")
        return []

class SearchEngine:
    def __init__(self, config=None, proxy=None, deep_scan=False):
        self.config = config or DEFAULT_CONFIG
        self.last = 0
        self.deep_scan = deep_scan
        self.rate_limit = self.config.get('rate_limit', 12.0)
        self.proxy = proxy
    
    def search(self, query, max_results=20):
        now = time.time()
        
        # Deep scans need extra jitter to avoid 403 Forbidden blocks from mass scraping
        base_jitter = 3.0 if self.deep_scan else 1.0
        max_jitter = 6.0 if self.deep_scan else 4.0
        jitter = random.uniform(base_jitter, max_jitter)
        
        wait = max(0, (self.rate_limit + jitter) - (now - self.last))
        
        if wait > 0:
            logger.info(f"Rate limiting: sleeping for {wait:.2f}s before next query...")
            time.sleep(wait)
        self.last = time.time()
        
        if self.proxy:
            logger.info(f"Using proxy: {self.proxy}")
        
        logger.info(f"Querying DuckDuckGo for: {query}")
        return ddg_search(query, max_results, proxy=self.proxy)


class PlatformProber:
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.platforms = self.config.get('platforms', {})
    
    def username_variants(self, username):

        base = re.sub(r'[^a-zA-Z0-9_.-]', '', (username or '').lower())
        variants = set()
        
        if not base:
            return []
        

        variants.add(base)
        variants.add(base.replace('.', ''))
        variants.add(base.replace('_', ''))
        variants.add(base.replace('-', ''))
        

        variants.add(base.replace('.', '_'))
        variants.add(base.replace('_', '.'))
        variants.add(base.replace('-', '_'))
        variants.add(base.replace('_', '-'))
        variants.add(base.replace('.', '-'))
        variants.add(base.replace('-', '.'))
        

        variants.add(f"_{base}")
        variants.add(f"{base}_")
        variants.add(f".{base}")
        variants.add(f"{base}.")
        variants.add(f"-{base}")
        variants.add(f"{base}-")
        

        variants.add(f"{base}123")
        variants.add(f"{base}01")
        variants.add(f"{base}1")
        variants.add(f"{base}0")
        variants.add(f"{base}99")
        variants.add(f"{base}00")
        

        if '.' in base:
            parts = base.split('.')
            if len(parts) == 2:

                variants.add(parts[0] + parts[1])
                variants.add(parts[0][0] + parts[1])
                variants.add(parts[0] + '_' + parts[1])
                variants.add(parts[0] + '-' + parts[1])

                variants.add(parts[0])

                variants.add(parts[1])
        

        if '_' in base:
            parts = base.split('_')
            if len(parts) == 2:
                variants.add(parts[0] + parts[1])
                variants.add(parts[0] + '.' + parts[1])
                variants.add(parts[0] + '-' + parts[1])
                variants.add(parts[0])
                variants.add(parts[1])
        

        if '-' in base:
            parts = base.split('-')
            if len(parts) == 2:
                variants.add(parts[0] + parts[1])
                variants.add(parts[0] + '_' + parts[1])
                variants.add(parts[0] + '.' + parts[1])
                variants.add(parts[0])
                variants.add(parts[1])
        


        variants.add(base[:30])
        variants.add(base[:15])
        variants.add(base[:12])
        variants.add(base[:10])
        variants.add(base[:8])
        


        filtered = sorted(v for v in variants if len(v) >= 3)
        
        logger.info(f"Generated {len(filtered)} username variants for '{username}'")
        return filtered
    
    def probe(self, username):
        results = []
        variants = self.username_variants(username)

        
        def _check_single(args):
            variant, platform_name, patterns = args
            local_results = []
            headers = {'User-Agent': random.choice(DEFAULT_CONFIG['user_agents'])}
            
            for p in patterns:
                if '{}' not in p:
                    continue
                url = p.format(variant)
                try:

                    r = requests.head(url, headers=headers, allow_redirects=True, timeout=5)
                    if r.status_code in (200, 301, 302):
                        local_results.append({
                            'platform': platform_name,
                            'url': r.url,
                            'username': variant,
                            'status': r.status_code,
                            'confidence': 80 if r.status_code == 200 else 60,
                            'snippet': '',
                            'timestamp': now_ts(),
                            'type': 'platform_probe'
                        })

                        break 
                except Exception:
                    pass
            return local_results


        tasks = []
        for v in variants:
            for plat, patterns in self.platforms.items():
                tasks.append((v, plat, patterns))
        



        logger.info(f"Probing {len(tasks)} combinations using 20 threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_check = {executor.submit(_check_single, task): task for task in tasks}
            for future in concurrent.futures.as_completed(future_to_check):
                try:
                    res = future.result()
                    if res:
                        results.extend(res)
                except Exception as e:
                    logger.debug(f"Probe error: {e}")
        
        return results


class EnhancedSearcher:
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
    
    def search_email(self, email):

        res = []
        if not email or '@' not in email:
            return res
        
        local = email.split('@',1)[0]
        

        candidates = [
            ('github', f'https://github.com/{local}', f'GitHub profile: @{local}'),
            ('twitter', f'https://twitter.com/{local}', f'Twitter profile: @{local}'),
            ('instagram', f'https://instagram.com/{local}', f'Instagram profile: @{local}'),
            ('reddit', f'https://reddit.com/user/{local}', f'Reddit profile: u/{local}'),
            ('medium', f'https://medium.com/@{local}', f'Medium author: @{local}'),
            ('pinterest', f'https://pinterest.com/{local}', f'Pinterest profile: {local}'),
            ('youtube', f'https://www.youtube.com/@{local}', f'YouTube channel: @{local}'),
            ('twitch', f'https://twitch.tv/{local}', f'Twitch channel: {local}'),
        ]
        
        def _check_email_platform(args):
            plat, url, desc = args
            headers = {'User-Agent': random.choice(self.config.get('user_agents', DEFAULT_CONFIG['user_agents']))}
            try:
                r = requests.head(url, headers=headers, allow_redirects=True, timeout=8)
                if r.status_code in (200,301,302):
                    return {
                        'platform': plat,
                        'url': r.url,
                        'confidence': 85,
                        'snippet': desc,
                        'timestamp': now_ts(),
                        'type': 'direct_check'
                    }
            except Exception:
                pass
            return None

        logger.info(f"Checking direct platform registrations for {email} (Concurrent)")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(candidates), 10)) as executor:
            futures = {executor.submit(_check_email_platform, c): c for c in candidates}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        res.append(result)
                except Exception:
                    pass
        
        return res
    
    def search_email_web(self, email, search_engine):

        queries = []
        local = email.split('@',1)[0]
        domain = email.split('@',1)[1] if '@' in email else ''
        
        logger.info(f"Generating comprehensive web search queries for {email}")
        

        queries.append(f'"{email}" (profile OR account OR user)')
        

        queries.append(f'"{email}" site:linkedin.com/in')
        queries.append(f'"{email}" site:facebook.com (profile OR about)')
        queries.append(f'"{email}" (site:twitter.com OR site:x.com) profile')
        queries.append(f'"{email}" site:instagram.com')
        

        queries.append(f'"{email}" site:github.com (commit OR author OR profile)')
        queries.append(f'"{email}" site:gitlab.com (commit OR profile)')
        queries.append(f'"{email}" site:bitbucket.org profile')
        

        queries.append(f'"{email}" (site:npmjs.com OR site:pypi.org OR site:rubygems.org) author')
        queries.append(f'"{email}" site:github.com gist')
        

        queries.append(f'"{email}" site:stackoverflow.com/users')
        queries.append(f'"{email}" site:reddit.com/user')
        queries.append(f'"{email}" site:quora.com profile')
        

        queries.append(f'"{email}" (site:crunchbase.com OR site:angellist.com) profile')
        queries.append(f'"{email}" site:about.me')
        queries.append(f'"{email}" site:gravatar.com')
        

        queries.append(f'"{email}" (site:medium.com/@{local} OR site:substack.com) author')
        queries.append(f'"{email}" site:youtube.com/@{local}')
        queries.append(f'"{email}" site:twitch.tv/{local}')
        

        queries.append(f'"{email}" (whois OR "domain owner" OR "registrant email")')
        queries.append(f'"{email}" site:opencorporates.com')
        

        queries.append(f'"{email}" (site:researchgate.net OR site:orcid.org) author')
        queries.append(f'"{email}" site:scholar.google.com author')
        queries.append(f'"{email}" (site:academia.edu OR site:researchgate.net) profile')
        

        queries.append(f'"{email}" (site:behance.net OR site:dribbble.com) portfolio')
        queries.append(f'"{email}" (site:flickr.com OR site:500px.com) photographer')
        

        queries.append(f'"{email}" (site:ebay.com OR site:etsy.com) seller')
        queries.append(f'"{email}" site:amazon.com seller')
        

        queries.append(f'"{email}" (site:indeed.com OR site:glassdoor.com) profile')
        queries.append(f'"{email}" (resume OR CV) filetype:pdf')
        

        queries.append(f'"{email}" (site:haveibeenpwned.com OR "data breach" OR compromised)')
        

        queries.append(f'"{email}" (site:pastebin.com OR site:paste.ee) -docs -api')
        

        queries.append(f'"{email}" (site:wordpress.com OR site:blogger.com OR site:tumblr.com) author')
        queries.append(f'"{email}" "contact" "about" -"how to" -"sign in"')
        

        queries.append(f'"{email}" (filetype:pdf OR filetype:doc) author')
        queries.append(f'"{email}" site:slideshare.net author')
        

        queries.append(f'"{email}" (telegram OR discord OR slack) username')
        

        queries.append(f'"{email}" (site:steam.com OR site:twitch.tv OR site:discord.com) profile')
        

        queries.append(f'"{email}" (site:flickr.com OR site:instagram.com) photos')
        

        queries.append(f'"{email}" (site:soundcloud.com OR site:spotify.com) artist')
        

        queries.append(f'"{email}" (site:leetcode.com OR site:hackerrank.com OR site:codewars.com) profile')
        
        logger.info(f"Generated {len(queries)} focused search queries for email investigation")
        return queries

    def search_phone(self, phone: str, country_code=None) -> list:

        findings = []
        if not phone:
            return findings
        
        orig = phone.strip()
        cleaned = re.sub(r'\D', '', phone)
        
        if len(cleaned) < 10:
            logger.debug(f"Phone '{phone}' ignored: fewer than 10 digits")
            return findings
        

        intelligence = extract_phone_intelligence(orig, country_code)
        
        if 'error' not in intelligence:
            findings.append({
                'type': 'phone_intelligence',
                'platform': 'phone_metadata',
                'url': '#',
                'confidence': 100,
                'snippet': f"Country: {intelligence['country']}, Carrier: {intelligence['carrier']}, Type: {intelligence['line_type']}",
                'timestamp': now_ts(),
                'intelligence': intelligence
            })
            

            if 'e164_format' in intelligence:
                cleaned = intelligence['e164_format'].replace('+', '')
        


        findings.append({
            'type': 'whatsapp_check',
            'platform': 'whatsapp',
            'url': f'https://wa.me/{cleaned}',
            'confidence': 75,
            'snippet': 'WhatsApp contact link',
            'timestamp': now_ts()
        })
        

        findings.append({
            'type': 'telegram_check',
            'platform': 'telegram',
            'url': f'https://t.me/{cleaned}',
            'confidence': 70,
            'snippet': 'Telegram contact link',
            'timestamp': now_ts()
        })
        

        findings.append({
            'type': 'signal_check',
            'platform': 'signal',
            'url': f'https://signal.me/#p/{cleaned}',
            'confidence': 65,
            'snippet': 'Signal contact link',
            'timestamp': now_ts()
        })
        

        findings.append({
            'type': 'viber_check',
            'platform': 'viber',
            'url': f'viber://add?number={cleaned}',
            'confidence': 60,
            'snippet': 'Viber contact link',
            'timestamp': now_ts()
        })
        

        spam_checks = check_spam_databases(cleaned)
        findings.extend(spam_checks)
        

        if orig.startswith('+') or len(cleaned) > 10:
            for f in findings:
                if 'note' not in f:
                    f['note'] = 'international'
        
        return findings
    
    def search_phone_web(self, phone, search_engine):

        queries = []
        cleaned = re.sub(r'\D', '', phone)
        
        if len(cleaned) < 10:
            return queries
        
        logger.info(f"Generating comprehensive web search queries for phone: {cleaned}")
        

        formats = [cleaned]
        if len(cleaned) == 10:
            formats.append(f"({cleaned[:3]}) {cleaned[3:6]}-{cleaned[6:]}")
            formats.append(f"{cleaned[:3]}-{cleaned[3:6]}-{cleaned[6:]}")
            formats.append(f"{cleaned[:3]}.{cleaned[3:6]}.{cleaned[6:]}")
        elif len(cleaned) > 10:
            formats.append(f"+{cleaned}")
            formats.append(f"+{cleaned[:2]} {cleaned[2:]}")
        

        for fmt in formats[:3]:
            queries.append(f'"{fmt}"')
        

        queries.append(f'"{cleaned}" site:facebook.com OR site:twitter.com OR site:instagram.com')
        queries.append(f'"{cleaned}" site:linkedin.com OR site:whatsapp.com')
        queries.append(f'"{cleaned}" site:telegram.org OR site:telegram.me')
        

        queries.append(f'"{cleaned}" whatsapp OR telegram OR signal OR viber')
        queries.append(f'"{cleaned}" "contact me" OR "call me" OR "text me"')
        

        queries.append(f'"{cleaned}" site:yellowpages.com OR site:whitepages.com')
        queries.append(f'"{cleaned}" site:yelp.com OR site:google.com/maps')
        queries.append(f'"{cleaned}" business OR company OR office')
        

        queries.append(f'"{cleaned}" site:linkedin.com profile')
        queries.append(f'"{cleaned}" resume OR CV OR "curriculum vitae"')
        

        queries.append(f'"{cleaned}" site:craigslist.org OR site:ebay.com OR site:facebook.com/marketplace')
        queries.append(f'"{cleaned}" "for sale" OR listing OR classified')
        

        queries.append(f'"{cleaned}" forum OR community OR discussion')
        queries.append(f'"{cleaned}" site:reddit.com OR site:quora.com')
        

        queries.append(f'"{cleaned}" site:zillow.com OR site:realtor.com OR site:trulia.com')
        queries.append(f'"{cleaned}" property OR real estate OR listing')
        

        queries.append(f'"{cleaned}" review OR rating OR testimonial')
        queries.append(f'"{cleaned}" site:yelp.com OR site:bbb.org')
        

        queries.append(f'"{cleaned}" "data breach" OR leak OR exposed')
        queries.append(f'"{cleaned}" database OR dump')
        

        queries.append(f'"{cleaned}" public record OR directory')
        queries.append(f'"{cleaned}" address OR location')
        

        queries.append(f'"{cleaned}" scam OR spam OR fraud OR complaint')
        queries.append(f'"{cleaned}" "who called" OR "unknown number"')
        

        queries.append(f'"{cleaned}" site:amazon.com OR site:ebay.com seller')
        queries.append(f'"{cleaned}" shop OR store OR merchant')
        

        queries.append(f'"{cleaned}" doctor OR lawyer OR attorney OR consultant')
        queries.append(f'"{cleaned}" service OR appointment')
        

        queries.append(f'"{cleaned}" site:indeed.com OR site:monster.com OR site:glassdoor.com')
        

        queries.append(f'"{cleaned}" news OR press OR article')
        

        queries.append(f'"{cleaned}" "contact us" OR "get in touch" OR "reach us"')
        

        queries.append(f'"{cleaned}" dating OR match OR profile')
        
        logger.info(f"Generated {len(queries)} search queries for phone investigation")
        return queries


class ResultFilter:
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.social_domains = set(self.config.get('social_domains', []))
        self.noise_domains = set(self.config.get('noise_domains', []))
        

        self.blacklist_patterns = [

            'docs.', '/docs/', '/doc/', '/documentation/', '/help/', '/support/',
            '/api/', '/developer/', '/developers/', '/reference/',

            '/login', '/signin', '/signup', '/register', '/forgot',
            '/terms', '/privacy', '/policy', '/about-us', '/contact',
            '/faq', '/tutorial', '/guide/', '/getting-started',

            'whois.', 'lookup', 'checker', 'validator', 'search.', 'find.',

            '.pdf', '.doc', '.pptx', '.xlsx', '.zip',

            'help.', 'support.', 'api.', 'developer.', 'docs.',
            'cdn.', 'static.', 'assets.', 'blog.', 'www.blog.',

            'stackoverflow.com/questions', 'stackexchange.com',
            'github.com/topics', 'github.com/features',
            'support.google.com', 'groups.google.com', 'developers.google.com',
            'signin.', 'login.', 'auth.',

            '/Gmail/', '/Googlemail', '/GoogleBusinessProfile/',
            '/httpsgmail', '/gmailcom', '/Google/',
        ]
        

        self.generic_page_keywords = [
            'gmail', 'googlemail', 'google business', 'email service',
            'free email', 'sign in', 'log in', 'create account',
            'unofficial page', 'fan page', 'community page'
        ]
        

        self.whitelist_patterns = [

            '/user/', '/profile/', '/@', '/p/',

            '/commit/', '/gist/', '/paste/',

            'github.com/' , 'twitter.com/', 'instagram.com/',
            'linkedin.com/in/', 'reddit.com/user/',
            'medium.com/@', 'youtube.com/@', 'tiktok.com/@',
        ]

    def calculate_relevance_score(self, result, query):
        score = 50
        url = (result.get('url') or '').lower()
        title = (result.get('title') or '').lower()
        snippet = (result.get('snippet') or '').lower()
        domain = urlparse(url).netloc.lower()
        

        for pattern in self.blacklist_patterns:
            if pattern in url or pattern in domain:
                logger.debug(f"Blacklisted URL: {url}")
                return 0
        

        for keyword in self.generic_page_keywords:
            if keyword in title.lower() or keyword in snippet.lower():

                if any(generic in snippet for generic in ['free email', 'email service', 'sign in', 'log in to', 'create account']):
                    logger.debug(f"Generic service page: {title[:50]}")
                    return 0
        

        query_lower = (query or '').lower()
        query_parts = query_lower.replace('"', '').split('@')
        if query_parts:
            query_username = query_parts[0]

            if query_username and len(query_username) > 3:
                if (query_username not in url and 
                    query_username not in title and 
                    query_username not in snippet):
                    logger.debug(f"Unrelated content (no query match): {title[:50]}")
                    return 0
        

        for pattern in self.whitelist_patterns:
            if pattern in url:
                score += 40
                break
        

        if any(s in domain for s in self.social_domains):
            score += 30
        

        if any(n in domain for n in self.noise_domains):
            score -= 40
        

        if 'support.google.com' in domain or 'groups.google.com' in domain or 'developers.google.com' in domain:
            return 0
        

        q = (query or '').lower()
        if q and q in url:
            score += 30
        if q and q in title:
            score += 20
        if q and q in snippet:
            score += 15
        

        if len(snippet) < 20:
            score -= 10
        

        if domain.endswith('.ru') or domain.endswith('.cn') or domain.endswith('.xyz'):
            score -= 10
        

        if len(url) > 150:
            score -= 10
        
        return max(0, min(100, score))

    def _is_spam(self, result):
        url = (result.get('url') or '').lower()
        title = (result.get('title') or '').lower()
        
        spam_indicators = [
            'autozparts', 'partsauto', 'product-', 
            'prefijostelefonicos', 'mas-informacion',
            'buy now', 'click here', 'limited offer'
        ]
        return any(ind in url or ind in title for ind in spam_indicators)
    
    def _is_generic_page(self, result):

        url = (result.get('url') or '').lower()
        title = (result.get('title') or '').lower()
        snippet = (result.get('snippet') or '').lower()
        
        generic_indicators = [
            'how to', 'tutorial', 'documentation', 'api reference',
            'getting started', 'guide to', 'introduction to',
            'what is', 'learn more', 'read more', 'find out'
        ]
        

        generic_profile_patterns = [
            'gmail gmail', 'my gmail', 'email gmail', 'gmail email',
            'googlemail', 'mail google', 'google mail'
        ]
        

        if 'linkedin.com' in url:
            for pattern in generic_profile_patterns:
                if pattern in title or pattern in snippet:
                    logger.debug(f"Generic LinkedIn profile: {title[:50]}")
                    return True
        
        return any(ind in title for ind in generic_indicators)

    def filter_results(self, results, query, min_score=40):
        filtered = []
        qlower = (query or '').lower()
        seen = set()
        
        for result in results:

            if result.get('type') == 'phone_intelligence':
                filtered.append(result)
                continue
                
            url = (result.get('url') or '') or ''
            if not url:
                continue
            if url in seen:
                continue
            seen.add(url)
            

            score = self.calculate_relevance_score(result, query)
            result['confidence'] = score
            

            if min_score == 0:
                filtered.append(result)
                continue
            

            if score == 0:
                continue
            
            domain = urlparse(url).netloc.lower()
            

            if self._is_spam(result):
                continue
            

            if self._is_generic_page(result):
                continue
            

            if score >= min_score:
                filtered.append(result)
        

        filtered.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        logger.info(f"Filtered {len(results)} results down to {len(filtered)} relevant findings")
        return filtered


def detect_anomalies(findings):
    anomalies = []
    domains = Counter()
    missing_snip = 0
    for f in findings:
        d = urlparse(f.get('url','')).netloc.lower()
        domains[d] += 1
        if not f.get('snippet'):
            missing_snip += 1
    total = len(findings) or 1
    for dom, cnt in domains.most_common(5):
        if cnt > max(5, total * 0.2):
            anomalies.append({'type':'domain_concentration','domain':dom,'count':cnt,'message':f"{cnt} results from {dom}."})
    if missing_snip > total * 0.5:
        anomalies.append({'type':'missing_snippet','count':missing_snip,'message':'Many results missing snippets (JS heavy or blocked).'})
    suspicious = [d for d in domains if d.endswith('.ru') or d.endswith('.cn') or d.endswith('.xyz')]
    if suspicious:
        anomalies.append({'type':'suspicious_tlds','domains':suspicious,'message':'Suspicious TLDs present: ' + ','.join(suspicious)})
    return anomalies


class ReportGenerator:
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.unicode_font = None
        if REPORTLAB:
            self.unicode_font = self._register_custom_font('Helvetica')

    def _sort_and_group(self, findings):

        high_conf = []
        other = []
        
        for f in findings:
            conf = f.get('confidence', 0)
            try:

                if f.get('type') == 'phone_intelligence':
                    high_conf.append(f)
                    continue
                    
                val = int(conf)
                if val >= 50:
                    high_conf.append(f)
                else:
                    other.append(f)
            except:
                if str(conf) in ['High', 'Medium', '100%']:
                    high_conf.append(f)
                else:
                    other.append(f)
                    

        high_conf.sort(key=lambda x: x.get('confidence', 0) if isinstance(x.get('confidence', 0), (int, float)) else 0, reverse=True)
        other.sort(key=lambda x: x.get('confidence', 0) if isinstance(x.get('confidence', 0), (int, float)) else 0, reverse=True)
        
        return high_conf, other

    
    def _register_custom_font(self, font_family):

        try:

            standard_fonts = ['Helvetica', 'Times-Roman', 'Courier', 'Symbol']
            if font_family in standard_fonts:
                return font_family
            

            possible_paths = []
            if os.name == 'nt':

                sys_font_dir = r'C:\Windows\Fonts'
                possible_paths = []
                

                font_map = {
                    'arial': 'arial.ttf',
                    'times new roman': 'times.ttf',
                    'courier new': 'cour.ttf',
                    'verdana': 'verdana.ttf',
                    'georgia': 'georgia.ttf',
                    'tahoma': 'tahoma.ttf',
                    'trebuchet ms': 'trebuc.ttf',
                    'comic sans ms': 'comic.ttf',
                    'impact': 'impact.ttf',
                    'segoe ui': 'segoeui.ttf',
                    'calibri': 'calibri.ttf',
                    'cambria': 'cambria.ttc',
                    'candara': 'candara.ttf',
                    'consolas': 'consola.ttf',
                    'constantia': 'constan.ttf',
                    'corbel': 'corbel.ttf',
                }
                
                clean_family = font_family.lower().strip()
                

                if clean_family in font_map:
                    possible_paths.append(os.path.join(sys_font_dir, font_map[clean_family]))
                

                possible_paths.append(os.path.join(sys_font_dir, f"{font_family}.ttf"))
                possible_paths.append(os.path.join(sys_font_dir, f"{font_family}.otf"))
                possible_paths.append(os.path.join(sys_font_dir, f"{font_family.replace(' ', '')}.ttf"))
                possible_paths.append(os.path.join(sys_font_dir, "arial.ttf"))
            else:

                possible_paths = [
                    f"/usr/share/fonts/truetype/{font_family}.ttf",
                    f"/usr/share/fonts/TPG/{font_family}.ttf",
                    f"~/.fonts/{font_family}.ttf"
                ]

            for font_path in possible_paths:
                if os.path.exists(font_path):
                    try:
                        pdfmetrics.registerFont(TTFont(font_family, font_path))

                        base, ext = os.path.splitext(font_path)
                        bold_path = f"{base}bd{ext}"
                        if not os.path.exists(bold_path):
                            bold_path = f"{base}b{ext}"
                        
                        if os.path.exists(bold_path):
                            pdfmetrics.registerFont(TTFont(f'{font_family}-Bold', bold_path))
                        else:
                            pdfmetrics.registerFont(TTFont(f'{font_family}-Bold', font_path))
                            
                        logger.info(f"✓ Registered font: {font_family}")
                        return font_family
                    except Exception:
                        continue

            logger.info(f"Font {font_family} not found (fast check), using Helvetica")
            return 'Helvetica'
            
        except Exception as e:
            logger.error(f"Error in font registration: {e}")
            return 'Helvetica'

    def generate_json(self, report, filename, report_config=None, categorize=False):
        path = os.path.join(self.output_dir, filename)
        config = report_config or DEFAULT_REPORT_CONFIG
        timestamp = format_timestamp(report.get('timestamp'), config['timezone'], show_local=False)
        
        findings = report.get('findings', [])
        if categorize:
             high, other = self._sort_and_group(findings)

             files_data = {
                 'high_confidence': high,
                 'other_findings': other
             }
             report['findings_structured'] = files_data

        
        enhanced_report = {
            **report,
            'report_config': config,
            'formatted_timestamp': timestamp
        }
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                json.dump(enhanced_report, fh, ensure_ascii=False, indent=2)

            time.sleep(0.1)
            logger.info(f"JSON report generated: {path}")
            return path
        except Exception as e:
            logger.error(f"Failed to generate JSON: {e}")
            return None

    def generate_txt(self, report, filename, report_config=None, categorize=False):
        path = os.path.join(self.output_dir, filename)
        config = report_config or DEFAULT_REPORT_CONFIG
        
        try:

            phone_intel = None
            for f in report.get('findings', []):
                if f.get('type') == 'phone_intelligence' and 'intelligence' in f:
                    phone_intel = f['intelligence']
                    break
            
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write("="*80 + "\n")
                fh.write(f"{config.get('report_title', 'OSINT INVESTIGATION REPORT')}\n")
                fh.write("="*80 + "\n\n")
                
                params = report.get('parameters', {})
                if params.get('email'):
                    fh.write(f"Email: {params['email']}\n")
                if params.get('phone'):
                    fh.write(f"Phone: {params['phone']}\n")
                    if params.get('country_code'):
                        fh.write(f"Country Code: +{params['country_code']}\n")
                if params.get('username'):
                    fh.write(f"Username: {params['username']}\n")
                

                if phone_intel and 'error' not in phone_intel:
                    fh.write("\n" + "-"*80 + "\n")
                    fh.write("PHONE INTELLIGENCE\n")
                    fh.write("-"*80 + "\n\n")
                    fh.write(f"E.164 Format: {phone_intel.get('e164_format', 'N/A')}\n")
                    fh.write(f"International Format: {phone_intel.get('international_format', 'N/A')}\n")
                    fh.write(f"Country: {phone_intel.get('country', 'Unknown')}\n")
                    fh.write(f"Carrier: {phone_intel.get('carrier', 'Unknown')}\n")
                    fh.write(f"Line Type: {phone_intel.get('line_type', 'Unknown')}\n")
                    fh.write(f"Valid Number: {'Yes' if phone_intel.get('valid') else 'No'}\n")
                    if phone_intel.get('timezone'):
                        fh.write(f"Timezone(s): {', '.join(phone_intel.get('timezone', []))}\n")
                    fh.write("\n")
                    
                timestamp = format_timestamp(report.get('timestamp'), config['timezone'], show_local=False)
                fh.write(f"Generated: {timestamp}\n")
                fh.write(f"Processing time: {report.get('processing_time',0):.2f}s\n")
                
                stats = report.get('statistics', {})
                fh.write(f"Total findings: {len(report.get('findings',[]))}\n")
                fh.write(f"Queries executed: {stats.get('queries_executed', 0)}\n")
                fh.write(f"Average confidence: {stats.get('average_confidence', 0)}%\n\n")
                
                sections = config.get('sections', ['summary', 'findings', 'anomalies'])
                
                if 'summary' in sections:
                    fh.write("=== EXECUTIVE SUMMARY ===\n\n")
                    platforms = Counter([f.get('platform','Unknown') for f in report.get('findings', [])])
                    for plat, cnt in platforms.most_common():
                        fh.write(f"  - {plat}: {cnt}\n")
                    fh.write("\n")
                
                if 'findings' in sections:
                    fh.write("=== DETAILED FINDINGS ===\n\n")
                    
                    all_findings = report.get('findings', [])
                    groups = []
                    
                    if categorize:
                        high, other = self._sort_and_group(all_findings)
                        if high: groups.append(("HIGH CONFIDENCE FINDINGS", high))
                        if other: groups.append(("OTHER FINDINGS", other))
                    else:
                        groups.append(("FINDINGS", all_findings))
                    
                    for title, findings_list in groups:
                        if categorize:
                            fh.write(f"--- {title} ---\n\n")
                            
                        for i, f in enumerate(findings_list, 1):
                            fh.write(f"{i}. [{f.get('platform','')}] {f.get('url','')}\n")
                            fh.write(f"   Confidence: {f.get('confidence',0)}%\n")
                            if config.get('include_previews', True):
                                snippet = clean_text(f.get('snippet') or '')
                                if snippet:
                                    fh.write(f"   Preview: {snippet[:200]}\n")
                            fh.write("\n")
                        fh.write("\n")
                
                if 'anomalies' in sections and report.get('anomalies'):
                    fh.write("=== ANOMALY DETECTION ===\n\n")
                    for a in report.get('anomalies', []):
                        fh.write(f"Warning: {a.get('message')}\n")
            

            time.sleep(0.1)
            logger.info(f"TXT report generated: {path}")
            return path
        except Exception as e:
            logger.error(f"Failed to generate TXT: {e}")
            return None

    def generate_html(self, report, filename, report_config=None, categorize=False):
        path = os.path.join(self.output_dir, filename)
        config = report_config or DEFAULT_REPORT_CONFIG
        timestamp = format_timestamp(report.get('timestamp'), config['timezone'], show_local=False)
        
        params = report.get('parameters', {})
        target_display = []
        if params.get('email'):
            target_display.append(f"<b>Email:</b> {params['email']}")
        if params.get('phone'):
            target_display.append(f"<b>Phone:</b> {params['phone']}")
        if params.get('username'):
            target_display.append(f"<b>Username:</b> {params['username']}")
        
        target_html = "<br/>".join(target_display) if target_display else 'Unknown'
        sections = config.get('sections', ['summary', 'findings'])
        
        html = f"""<!doctype html>
<html>
<head>
    <meta charset='utf-8'>
    <title>{config.get('report_title', 'OSINT Report')}</title>
    <style>
        body {{ font-family: {config['font_family']}, Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; text-align: center; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #f8f9fa; }}
        .high {{ color: #27ae60; font-weight: bold; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #e74c3c; }}
    </style>
</head>
<body>
    <h1>{config.get('report_title', 'OSINT Report')}</h1>
    <div style="text-align:center; margin:20px 0;">
        {target_html}<br/>
        <small>Generated: {timestamp}</small>
    </div>
"""
        
        if 'summary' in sections:
            platforms = Counter([f.get('platform','Unknown') for f in report.get('findings', [])])
            html += "<h2>Summary</h2><table><tr><th>Platform</th><th>Count</th></tr>"
            for plat, cnt in platforms.most_common():
                html += f"<tr><td>{plat}</td><td>{cnt}</td></tr>"
            html += "</table>"
        
        if 'findings' in sections:
            html += "<h2>Findings</h2>"
            
            all_findings = report.get('findings', [])
            groups = []
            
            if categorize:
                high, other = self._sort_and_group(all_findings)
                if high: groups.append(("High Confidence Findings", high))
                if other: groups.append(("Other Findings", other))
            else:
                groups.append(("", all_findings))
            
            for title, findings_list in groups:
                if title:
                    html += f"<h3>{title}</h3>"
                
                html += "<table><tr><th>#</th><th>Platform</th><th>URL</th><th>Confidence</th></tr>"
                for i, f in enumerate(findings_list, 1):
                    conf = f.get('confidence', 0)
                    conf_class = "high" if conf >= 80 else "medium" if conf >= 60 else "low"
                    html += f"<tr><td>{i}</td><td>{f.get('platform','')}</td><td><a href='{f.get('url','')}'>{f.get('url','')}</a></td><td class='{conf_class}'>{conf}%</td></tr>"
                html += "</table>"
        
        html += "</body></html>"
        
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(html)

            time.sleep(0.1)
            logger.info(f"HTML report generated: {path}")
            return path
        except Exception as e:
            logger.error(f"Failed to generate HTML: {e}")
            return None

    def generate_pdf(self, report, filename, report_config=None, categorize=False):
        if not REPORTLAB:
            logger.warning("ReportLab missing; skipping PDF generation.")
            return None

        try:
            path = os.path.join(self.output_dir, filename)
            config = report_config or DEFAULT_REPORT_CONFIG


            page_size_map = {'A4': A4, 'Letter': LETTER, 'Legal': LEGAL}
            pagesize = page_size_map.get(config.get('page_size'), A4)


            requested_font = config.get('font_family', 'Helvetica')
            registered_font = self._register_custom_font(requested_font)
            

            logger.info(f"PDF Generation - Requested: '{requested_font}' | Using: '{registered_font}'")
            

            try:
                from reportlab.pdfbase.pdfmetrics import getFont
                getFont(registered_font)
                logger.info(f"✓ Font '{registered_font}' verified in ReportLab")
            except Exception as e:
                logger.warning(f"Font verification failed: {e}, falling back to Helvetica")
                registered_font = 'Helvetica'

            sections = config.get('sections', [])
            max_preview_len = config.get('max_preview_length', 300)
            font_size = config.get('font_size', 10)
            title_size = config.get('title_font_size', 16)
            heading_size = config.get('heading_font_size', 14)

            doc = SimpleDocTemplate(
                path,
                pagesize=pagesize,
                rightMargin=36,
                leftMargin=36,
                topMargin=36,
                bottomMargin=36
            )

            styles = getSampleStyleSheet()


            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=title_size,
                fontName=f'{registered_font}-Bold',
                spaceAfter=12,
                alignment=1
            )


            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=heading_size,
                fontName=f'{registered_font}-Bold',
                spaceAfter=8,
                spaceBefore=12
            )


            normal_style = ParagraphStyle(
                'CustomNormal',
                parent=styles['Normal'],
                fontSize=font_size,
                fontName=registered_font,
                leading=font_size + 2
            )

            story = []


            story.append(Paragraph(
                config.get('report_title', 'OSINT Investigation Report'),
                title_style
            ))
            story.append(Spacer(1, 12))


            params = report.get('parameters', {})
            if params.get('email'):
                story.append(Paragraph(f"<b>Email:</b> {params['email']}", normal_style))
            if params.get('phone'):
                story.append(Paragraph(f"<b>Phone:</b> {params['phone']}", normal_style))
                if params.get('country_code'):
                    story.append(Paragraph(f"<b>Country Code:</b> +{params['country_code']}", normal_style))
            if params.get('username'):
                story.append(Paragraph(f"<b>Username:</b> {params['username']}", normal_style))

            story.append(Spacer(1, 12))
            

            phone_intel = None
            for f in report.get('findings', []):
                if f.get('type') == 'phone_intelligence' and 'intelligence' in f:
                    phone_intel = f['intelligence']
                    break
            
            if phone_intel and 'error' not in phone_intel:
                story.append(Paragraph("Phone Intelligence", heading_style))
                
                intel_data = [
                    ['E.164 Format', phone_intel.get('e164_format', 'N/A')],
                    ['International Format', phone_intel.get('international_format', 'N/A')],
                    ['Country', phone_intel.get('country', 'Unknown')],
                    ['Carrier', phone_intel.get('carrier', 'Unknown')],
                    ['Line Type', phone_intel.get('line_type', 'Unknown')],
                    ['Valid Number', 'Yes' if phone_intel.get('valid') else 'No'],
                ]
                
                if phone_intel.get('timezone'):
                    intel_data.append(['Timezone(s)', ', '.join(phone_intel.get('timezone', []))])
                
                intel_table = Table(intel_data, colWidths=[150, 250])
                intel_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), f'{registered_font}-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), font_size),
                    ('FONTNAME', (0, 1), (-1, -1), registered_font),
                    ('FONTSIZE', (0, 1), (-1, -1), font_size),
                    ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('TOPPADDING', (0, 1), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
                ]))
                
                story.append(intel_table)
                story.append(Spacer(1, 20))


            timestamp = format_timestamp(
                report.get('timestamp'),
                config.get('timezone', 'UTC'),
                show_local=False
            )
            story.append(Paragraph(f"<b>Generated:</b> {timestamp}", normal_style))
            story.append(Paragraph(
                f"<b>Total Findings:</b> {len(report.get('findings', []))}",
                normal_style
            ))
            story.append(Spacer(1, 20))


            if 'summary' in sections:
                story.append(Paragraph("Executive Summary", heading_style))

                platforms = Counter(
                    [f.get('platform', 'Unknown') for f in report.get('findings', [])]
                )

                table_data = [['Platform', 'Count']]
                for plat, cnt in platforms.most_common(10):
                    table_data.append([plat, str(cnt)])

                table = Table(table_data, colWidths=[300, 100])
                

                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), f'{registered_font}-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), font_size),
                    ('FONTNAME', (0, 1), (-1, -1), registered_font),
                    ('FONTSIZE', (0, 1), (-1, -1), font_size),
                    ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('TOPPADDING', (0, 1), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
                ]))

                story.append(table)
                story.append(Spacer(1, 20))


            if 'findings' in sections:
                story.append(Paragraph("Detailed Findings", heading_style))
                story.append(Spacer(1, 6))
                
                all_findings = report.get('findings', [])
                groups = []
                
                if categorize:
                    high, other = self._sort_and_group(all_findings)
                    if high: groups.append(("High Confidence Findings", high))
                    if other: groups.append(("Other Findings", other))
                else:
                    groups.append(("", all_findings))
                
                for title, findings_list in groups:
                    if title:
                         story.append(Paragraph(title, heading_style))
                         story.append(Spacer(1, 6))

                    table_data = [['Platform', 'URL', 'Conf']]
                    for f in findings_list:
                        conf = f.get('confidence', 0)
                        

                        url = f.get('url', '')

                        url_para = Paragraph(url, normal_style)
                        plat_para = Paragraph(f.get('platform', ''), normal_style)
                        conf_para = Paragraph(f"{conf}%", normal_style)
                        
                        table_data.append([
                            plat_para,
                            url_para,
                            conf_para
                        ])
                    
                    if len(table_data) > 1:

                        t = Table(table_data, colWidths=[90, 370, 50])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('FONTNAME', (0, 0), (-1, 0), f'{registered_font}-Bold'),
                            ('FONTSIZE', (0, 0), (-1, 0), font_size),
                            ('FONTNAME', (0, 1), (-1, -1), registered_font),
                            ('FONTSIZE', (0, 1), (-1, -1), font_size),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                            ('LEFTPADDING', (0, 0), (-1, -1), 4),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                            ('TOPPADDING', (0, 0), (-1, -1), 2),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                        ]))
                        story.append(t)
                        story.append(Spacer(1, 10))
                    else:
                        story.append(Paragraph("No findings in this category.", normal_style))
                        story.append(Spacer(1, 10))


            if 'statistics' in sections:
                story.append(Paragraph("Statistics", heading_style))
                
                stats = report.get('statistics', {})
                story.append(Paragraph(
                    f"<b>Total Findings:</b> {stats.get('total_findings', 0)}",
                    normal_style
                ))
                story.append(Paragraph(
                    f"<b>Average Confidence:</b> {stats.get('average_confidence', 0)}%",
                    normal_style
                ))
                story.append(Paragraph(
                    f"<b>Queries Executed:</b> {stats.get('queries_executed', 0)}",
                    normal_style
                ))
                
                story.append(Spacer(1, 10))


            if 'anomalies' in sections and report.get('anomalies'):
                story.append(Paragraph("Anomaly Detection", heading_style))
                
                for a in report.get('anomalies', []):
                    story.append(Paragraph(
                        f"• {a.get('message', '')}",
                        normal_style
                    ))
                    story.append(Spacer(1, 6))


            doc.build(story)
            

            time.sleep(0.2)
            logger.info(f"✓ PDF successfully generated: {path}")
            logger.info(f"✓ Font used: {registered_font}")
            return path

        except Exception as e:
            logger.exception(f"PDF generation failed: {e}")
            return None


class ProfileAnalyzer:

    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

    def analyze(self, url):

        if not BEAUTIFULSOUP_AVAILABLE:
            return {}

        try:

            time.sleep(random.uniform(0.5, 1.5))
            

            resp = self.session.get(url, timeout=5, allow_redirects=True)
            if resp.status_code != 200:
                logger.debug(f"Failed to analyze {url}: Status {resp.status_code}")
                return {}
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            data = {
                'title': '',
                'description': '',
                'image': '',
                'bio': '',
                'followers': ''
            }
            

            if soup.title:
                data['title'] = soup.title.string.strip()
            

            meta_desc = soup.find('meta', attrs={'name': 'description'}) or \
                        soup.find('meta', attrs={'property': 'og:description'}) or \
                        soup.find('meta', attrs={'name': 'twitter:description'})
            if meta_desc:
                data['description'] = meta_desc.get('content', '').strip()
                

            meta_img = soup.find('meta', attrs={'property': 'og:image'}) or \
                       soup.find('meta', attrs={'name': 'twitter:image'})
            if meta_img:
                data['image'] = meta_img.get('content', '')
            

            domain = urlparse(url).netloc.lower()
            

            if 'github.com' in domain:

                bio_tag = soup.find(class_='user-profile-bio')
                if bio_tag:
                    data['bio'] = bio_tag.get_text(strip=True)

                followers_link = soup.select_one("a[href$='?tab=followers'] span")
                if followers_link:
                    data['followers'] = followers_link.get_text(strip=True) + " followers"
            

            elif 'instagram.com' in domain:
                if data['description']:

                    parts = data['description'].split('-')
                    if len(parts) > 0:
                        data['followers'] = parts[0].strip()
            

            if not data['bio'] and data['description']:
                data['bio'] = data['description']

            return data
            
        except Exception as e:
            logger.debug(f"Deep dive failed for {url}: {e}")
            return {}

class GraphGenerator:

    
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def generate(self, results, target_id, timestamp):

        try:
            nodes = []
            edges = []
            

            nodes.append({
                "id": 0, 
                "label": target_id, 

                "shape": "dot",
                "size": 30,
                "font": {"size": 20, "color": "#ffffff"}
            })
            

            for i, item in enumerate(results, 1):
                platform = item.get('platform', 'Unknown')
                url = item.get('url', '#')
                confidence = item.get('confidence', 'Unknown')
                

                conf_val = item.get('confidence', 0)
                try:
                    conf_score = int(conf_val)
                    if conf_score >= 80: color = "#4CAF50"
                    elif conf_score >= 50: color = "#FF9800"
                    else: color = "#9E9E9E"

                except:

                    if str(conf_val) == "High": color = "#4CAF50"
                    elif str(conf_val) == "Medium": color = "#FF9800" 
                    else: color = "#9E9E9E"
                

                nodes.append({
                    "id": i,
                    "label": platform,

                    "color": color,
                    "shape": "dot",
                    "size": 15
                })
                

                edges.append({
                    "from": 0,
                    "to": i,
                    "length": 150
                })
                

            html_content = self._get_html_template(nodes, edges, target_id, timestamp)
            


            filename = f"graph_{target_id}_{timestamp}.html"
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
                
            return filepath
            
        except Exception as e:
            logger.error(f"Graph generation failed: {e}")
            return None

    def _get_html_template(self, nodes, edges, target, timestamp):
        nodes_json = json.dumps(nodes)
        edges_json = json.dumps(edges)
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Investigation Graph - {target}</title>
    <style>
        body {{ margin: 0; padding: 0; background-color: #111; color: #eee; font-family: 'Segoe UI', sans-serif; }}
        #mynetwork {{ width: 100vw; height: 100vh; }}
        .controls {{ 
            position: absolute; top: 10px; left: 10px; z-index: 100; 
            background: rgba(30,30,30,0.9); padding: 15px; border-radius: 8px; 
            box-shadow: 0 4px 15px rgba(0,0,0,0.5); border: 1px solid #444;
            max-width: 250px;
        }}
        h2 {{ margin: 0 0 5px 0; font-size: 18px; color: #fff; border-bottom: 1px solid #555; padding-bottom: 5px; }}
        p {{ margin: 0 0 10px 0; font-size: 12px; color: #aaa; }}
        .legend {{ margin-bottom: 15px; }}
        .legend-item {{ display: flex; align-items: center; margin-bottom: 5px; font-size: 13px; }}
        .dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; display: inline-block; }}
        
        .control-group {{ margin-bottom: 15px; border-top: 1px solid #444; padding-top: 10px; }}
        .control-label {{ font-size: 12px; color: #ccc; margin-bottom: 5px; display: block; font-weight: bold; }}
        
        button {{ 
            background: #444; color: #fff; border: 1px solid #555; 
            padding: 5px 10px; cursor: pointer; margin-right: 5px; margin-bottom: 5px;
            border-radius: 4px; font-size: 12px; transition: background 0.2s;
        }}
        button:hover {{ background: #555; border-color: #777; }}
        button:active {{ background: #666; }}
        
        select {{
            background: #333; color: #fff; border: 1px solid #555;
            padding: 5px; border-radius: 4px; width: 100%; margin-bottom: 5px;
        }}
        
        .zoom-controls {{ position: absolute; bottom: 20px; right: 20px; z-index: 100; display: flex; flex-direction: column; }}
        .zoom-btn {{ width: 40px; height: 40px; font-size: 20px; text-align: center; margin-top: 5px; }}
        
    </style>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
</head>
<body>
    <div class="controls">
        <h2>Target: {target}</h2>
        <p>{timestamp}</p>
        
        <div class="control-group">
            <span class="control-label">Layout Mode</span>
            <select id="layoutSelect" onchange="changeLayout()">
                <option value="standard">Standard (Force)</option>
                <option value="hierarchical">Hierarchical (Tree)</option>
                <option value="circle">Circle</option>
            </select>
        </div>
        
        <div class="control-group">
             <span class="control-label">Physics</span>
             <button onclick="togglePhysics()" id="btnPhysics">Freeze</button>
             <button onclick="fitGraph()">Fit Graph</button>
        </div>
        
        <div class="control-group">
             <span class="control-label">Export</span>
            <button onclick="saveImage('jpg')">Save JPG</button>
            <button onclick="saveImage('png')">Save PNG</button>
        </div>
        
        <div class="legend">
            <span class="control-label">Legend</span>
            <div class="legend-item"><span class="dot" style="background:#D50000"></span> Target</div>
            <div class="legend-item"><span class="dot" style="background:#4CAF50"></span> High Confidence</div>
            <div class="legend-item"><span class="dot" style="background:#FF9800"></span> Medium Confidence</div>
            <div class="legend-item"><span class="dot" style="background:#9E9E9E"></span> Low Confidence</div>
        </div>
        <!-- Hidden input for filename storage -->
        <input type="hidden" id="graph-filename" value="graph_{target}">
    </div>
    
    <div class="zoom-controls">
        <button class="zoom-btn" onclick="zoomIn()">+</button>
        <button class="zoom-btn" onclick="zoomOut()">-</button>
         <button class="zoom-btn" onclick="fitGraph()" style="font-size: 12px;">Fit</button>
    </div>

    <div id="mynetwork"></div>
    
    <script type="text/javascript">
        var nodes = new vis.DataSet({nodes_json});
        var edges = new vis.DataSet({edges_json});
        var container = document.getElementById('mynetwork');
        var data = {{ nodes: nodes, edges: edges }};
        
        var options = {{
            nodes: {{
                font: {{ color: '#eeeeee', size: 14 }},
                borderWidth: 2,
                shadow: true,
                color: {{ border: '#222', highlight: {{ border: '#222', background: '#FFF' }} }}
            }},
            edges: {{
                color: {{ color: '#555555', highlight: '#00ccff', opacity: 0.8 }},
                width: 2,
                shadow: true,
                smooth: {{ type: 'continuous' }}
            }},
            physics: {{
                stabilization: {{ enabled: true, iterations: 1000, updateInterval: 25 }},
                barnesHut: {{
                    gravitationalConstant: -30000,
                    centralGravity: 0.3,
                    springLength: 150,
                    springConstant: 0.04,
                    damping: 0.09,
                    avoidOverlap: 0.1
                }}
            }},
            layout: {{
                randomSeed: 2
            }},
            interaction: {{ 
                hover: true, 
                tooltipDelay: 200, 
                zoomView: true, 
                dragView: true,
                navigationButtons: false
            }}
        }};
        
        var network = new vis.Network(container, data, options);
        
        // Auto-fit after stabilization
        network.once("stabilizationIterationsDone", function() {{
            network.fit({{ 
                animation: {{ duration: 1000, easingFunction: "easeInOutQuad" }}
            }});
        }});
        
        // --- Functions ---
        
        function changeLayout() {{
            var layout = document.getElementById('layoutSelect').value;
             if (layout === 'hierarchical') {{
                network.setOptions({{
                    layout: {{
                        hierarchical: {{
                            enabled: true,
                            direction: 'UD',
                            sortMethod: 'directed',
                            nodeSpacing: 150,
                            levelSeparation: 150
                        }}
                    }},
                     physics: {{ enabled: false }} // Hierarchy uses its own placement
                }});
                document.getElementById('btnPhysics').innerText = "Physics Disabled";
                document.getElementById('btnPhysics').disabled = true;
            }} else if (layout === 'circle') {{
                // Quick circle layout hack or use physics with central gravity
                 network.setOptions({{
                    layout: {{ hierarchical: false }},
                    physics: {{
                        enabled: true,
                         solver: 'repulsion',
                         repulsion: {{ nodeDistance: 200, centralGravity: 0.2 }}
                    }}
                }});
                 document.getElementById('btnPhysics').innerText = "Freeze";
                 document.getElementById('btnPhysics').disabled = false;
            }} else {{
                // Standard
                network.setOptions({{
                    layout: {{ hierarchical: false }},
                    physics: {{
                        enabled: true,
                        solver: 'barnesHut',
                         barnesHut: {{
                             gravitationalConstant: -30000,
                             springLength: 150
                         }}
                    }}
                }});
                document.getElementById('btnPhysics').innerText = "Freeze";
                document.getElementById('btnPhysics').disabled = false;
            }}
            network.fit();
        }}

        function togglePhysics() {{
            var btn = document.getElementById('btnPhysics');
            if (network.physics.physicsEnabled) {{
                network.setOptions({{ physics: {{ enabled: false }} }});
                btn.innerText = "Unfreeze";
            }} else {{
                network.setOptions({{ physics: {{ enabled: true }} }});
                btn.innerText = "Freeze";
            }}
        }}
        
        function fitGraph() {{
            network.fit({{ animation: {{ duration: 1000 }} }});
        }}
        
        function zoomIn() {{
            var scale = network.getScale() + 0.3;
             network.moveTo({{ scale: scale, animation: {{ duration: 300 }} }});
        }}
        
        function zoomOut() {{
            var scale = network.getScale() - 0.3;
            if(scale < 0.1) scale = 0.1;
             network.moveTo({{ scale: scale, animation: {{ duration: 300 }} }});
        }}

        function saveImage(type) {{
            var networkCanvas = container.getElementsByTagName('canvas')[0];
            var scaleFactor = 4;
            // ... (Same save logic as before) ...
            var currentScale = network.getScale();
            var currentPos = network.getViewPosition();
            var originalWidth = container.style.width;
             var originalHeight = container.style.height;
             
            container.style.width = (container.offsetWidth * scaleFactor) + "px";
            container.style.height = (container.offsetHeight * scaleFactor) + "px";
            network.setSize((container.offsetWidth) + "px", (container.offsetHeight) + "px");
            network.redraw();
            
            setTimeout(function() {{
                var image = container.getElementsByTagName('canvas')[0].toDataURL("image/" + type, 1.0);
                
                // Restore
                container.style.width = "100vw";
                container.style.height = "100vh";
                network.setSize("100%", "100%");
                network.moveTo({{position: currentPos, scale: currentScale}});
                
                var link = document.createElement('a');
                var fnameInput = document.getElementById('graph-filename');
                var fname = fnameInput ? fnameInput.value : "investigation_graph";
                
                link.download = fname + "." + type;
                link.href = image;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }}, 500);
        }}
    </script>
</body>
</html>
"""

    def _clean_filename(self, text):

        return re.sub(r'[^\w\-_\.]', '_', text)

import subprocess
import asyncio

def run_holehe(email):
    findings = []
    try:
        logger.info(f"Running Holehe API against {email}...")
        res = subprocess.run(
            ["holehe", email, "--only-used", "--no-color", "--no-clear"], 
            capture_output=True, text=True, timeout=120
        )
        for line in res.stdout.split('\n'):
            line = line.strip()
            if line.startswith("[+]") and "Email used" not in line:
                site = line.replace("[+]", "").strip()
                findings.append({
                    'platform': site,
                    'title': f"Registered Account: {site}",
                    'url': f"https://{site}",
                    'snippet': f"Holehe API verified that {email} is actively registered on {site}.",
                    'type': 'api_probe',
                    'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    'confidence': 98
                })
    except Exception as e:
        logger.warning(f"Holehe execution failed: {e}")
    return findings

def run_sherlock(username):
    findings = []
    try:
        logger.info(f"Running Sherlock API against {username}...")
        res = subprocess.run(
            ["sherlock", username, "--print-found", "--no-color", "--timeout", "10"],
            capture_output=True, text=True, timeout=400
        )
        for line in res.stdout.split('\n'):
            line = line.strip()
            if line.startswith("[+]"):
                parts = line.replace("[+]", "").split(":", 1)
                if len(parts) == 2:
                    site = parts[0].strip()
                    url = parts[1].strip()
                    findings.append({
                        'platform': site.lower().replace(" ", ""),
                        'title': f"Sherlock Output: Profile on {site}",
                        'url': url,
                        'snippet': f"Sherlock API identified a public profile for {username} on {site}.",
                        'type': 'api_probe',
                        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        'confidence': 95
                    })
    except Exception as e:
        logger.warning(f"Sherlock execution failed: {e}")
    return findings

def run_truecaller(phone, auth_id):
    findings = []
    if not auth_id:
        return findings
    try:
        logger.info(f"Running Truecaller API against {phone}...")
        import truecallerpy
        from truecallerpy.search import search_phonenumber
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        res = loop.run_until_complete(search_phonenumber(phone.replace('+', ''), "", auth_id))
        
        if res and "data" in res and res["data"]:
            data = res["data"][0]
            name = data.get("name", "Unknown")
            carrier = data.get("phones", [{}])[0].get("carrier", "Unknown")
            score = data.get("score", 0)
            findings.append({
                'platform': 'truecaller',
                'title': f"Truecaller Identity: {name}",
                'url': "https://truecaller.com",
                'snippet': f"Truecaller fetched caller ID '{name}'. Carrier: {carrier}. Spam Score: {score}",
                'type': 'api_probe',
                'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                'confidence': 100
            })
    except Exception as e:
        logger.warning(f"Truecaller execution failed: {e}")
    return findings


class OSINTEngine:
    def __init__(self, config=None, proxy=None, truecaller_id=None, deep_scan=False):
        self.config = config or DEFAULT_CONFIG
        self.truecaller_id = truecaller_id
        self.deep_scan = deep_scan
        self.search_engine = SearchEngine(self.config, proxy=proxy, deep_scan=deep_scan)
        self.platform_prober = PlatformProber(self.config)
        self.enhanced_searcher = EnhancedSearcher(self.config)
        self.result_filter = ResultFilter(self.config)
        self.report_generator = ReportGenerator()
        self.profile_analyzer = ProfileAnalyzer()
        self.graph_generator = GraphGenerator()

    def investigate(self, email=None, phone=None, username=None, country_code=None, max_search=30, progress_callback=None):
        start_time = time.time()
        
        identifier_parts = []
        if email:
            identifier_parts.append(f"email:{email}")
        if phone:
            identifier_parts.append(f"phone:{phone}")
        if username:
            identifier_parts.append(f"username:{username}")
        
        identifier = " | ".join(identifier_parts) if identifier_parts else 'unknown'
        
        if progress_callback:
            progress_callback(0, "Initializing")
        
        findings = []
        queries = []
        

        if email:
            if progress_callback:
                progress_callback(5, "Checking email platforms via direct APIs (Holehe)")
            
            api_findings = run_holehe(email)
            findings.extend(api_findings)
            
            findings.extend(self.enhanced_searcher.search_email(email))
            
            if progress_callback:
                progress_callback(10, "Generating email search queries")
            

            email_queries = self.enhanced_searcher.search_email_web(email, self.search_engine)
            
            email_queries.append(f'site:haveibeenpwned.com "{email}"')
            email_queries.append(f'site:gravatar.com "{email}"')
            email_queries.append(f'site:pinterest.com "{email}"') 
            email_queries.append(f'site:skype.com "{email}"')
            email_queries.append(f'intext:"{email}" filetype:pdf OR filetype:doc OR filetype:xls')

            limit = len(email_queries) if self.deep_scan else 25
            queries.extend(email_queries[:limit])
            
            logger.info(f"Added {len(email_queries[:limit])} email investigation queries")
        

        if phone:
            if progress_callback:
                progress_callback(15, "Extracting phone intelligence (Truecaller API)")
            
            findings.extend(run_truecaller(phone, self.truecaller_id))
            findings.extend(self.enhanced_searcher.search_phone(phone, country_code))
            
            if progress_callback:
                progress_callback(18, "Generating phone search queries")
            

            phone_queries = self.enhanced_searcher.search_phone_web(phone, self.search_engine)
            
            phone_queries.append(f'site:truecaller.com "{phone}"')
            phone_queries.append(f'site:sync.me "{phone}"')
            phone_queries.append(f'site:callerid.com "{phone}"')
            phone_queries.append(f'"{phone}" "contact me" OR "call me" OR "whatsapp"')
            
            limit = len(phone_queries) if self.deep_scan else 20
            queries.extend(phone_queries[:limit])
            
            logger.info(f"Added {len(phone_queries[:limit])} phone investigation queries")
        

        if username:
            if progress_callback:
                progress_callback(20, "Probing username variants (Sherlock API)")
            

            findings.extend(run_sherlock(username))
            
            variants = self.platform_prober.username_variants(username)
            logger.info(f"Investigating {len(variants)} username variants")
            

            findings.extend(self.platform_prober.probe(username))
            
            limit = len(variants) if self.deep_scan else 8
            for v in variants[:limit]:
                queries.append(f'"{v}" site:instagram.com')
                queries.append(f'"{v}" site:twitter.com OR site:x.com')
                queries.append(f'"{v}" site:github.com')
                queries.append(f'"{v}" site:reddit.com')
                queries.append(f'"{v}" site:tiktok.com')
                queries.append(f'"{v}" site:pinterest.com')
                queries.append(f'"{v}" site:t.me OR site:telegram.me')
                queries.append(f'"{v}" site:linkedin.com')
        
        total_q = len(queries)
        

        
        def _execute_search(args):
            idx, q = args
            if progress_callback and idx % 2 == 0:
                progress_pct = 25 + int((idx/total_q)*60)
                progress_callback(progress_pct, f"Searching web ({idx}/{total_q})...")
            
            try:
                results_per_query = max(3, min(15, max_search // max(1, total_q)))

                return self.search_engine.search(q, max_results=results_per_query), q
            except Exception as e:
                logger.debug(f"Search error for {q}: {e}")
                return [], q


        logger.info(f"Executing {len(queries)} search queries with parallel workers...")
        
        workers = 1 if self.deep_scan else 2
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_query = {executor.submit(_execute_search, (i, q)): q for i, q in enumerate(queries)}
            
            for future in concurrent.futures.as_completed(future_to_query):
                try:
                    results, original_query = future.result()
                    for r in results:
                        url = r.get('url')
                        if not url:
                            continue
                        item = {
                            'platform': urlparse(url).netloc,
                            'url': url,
                            'title': clean_text(r.get('title','')),
                            'snippet': clean_text(r.get('snippet','')),
                            'timestamp': now_ts(),
                            'type': 'web_search',
                            'query': original_query[:50]
                        }
                        findings.append(item)
                except Exception as e:
                    logger.error(f"Search worker failed: {e}")
        
        if progress_callback:
            progress_callback(85, "Filtering results")
        

        filtered = self.result_filter.filter_results(findings, email or phone or username, min_score=0)
        

        unique = []
        seen = set()
        for f in filtered:
            u = f.get('url') or ''
            if u and u not in seen:
                seen.add(u)
                unique.append(f)
        

        anomalies = detect_anomalies(unique)
        

        platforms = Counter([f.get('platform','Unknown') for f in unique])
        confidences = [f.get('confidence',0) for f in unique]
        avg_conf = (sum(confidences)/len(confidences)) if confidences else 0
        processing_time = time.time() - start_time
        
        report = {
            'target': identifier,
            'timestamp': now_ts(),
            'processing_time': processing_time,
            'findings': unique,
            'statistics': {
                'total_findings': len(unique),
                'platforms': dict(platforms),
                'average_confidence': round(avg_conf,1),
                'high_confidence_findings': len([x for x in unique if x.get('confidence',0) > 70]),
                'queries_executed': len(queries)
            },
            'parameters': {
                'email': email, 
                'phone': phone,
                'country_code': country_code,
                'username': username, 
                'max_search': max_search
            },
            'anomalies': anomalies
        }
        
        if progress_callback:
            progress_callback(90, "Analyzing profiles (Deep Dive)...")
            

        for item in unique:
            if item.get('confidence', 0) > 60 or item.get('type') == 'username_search':
                try:
                    meta = self.profile_analyzer.analyze(item['url'])
                    if meta:
                        item['metadata'] = meta
                        if not item.get('snippet') and meta.get('bio'):
                            item['snippet'] = meta['bio']
                        if not item.get('title') and meta.get('title'):
                            item['title'] = meta['title']
                except Exception as e:
                    logger.debug(f"Analysis failed for {item['url']}: {e}")

        if progress_callback:
            progress_callback(95, "Generating validation report")


        target_id = username or email or phone or "target"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        

        safe_target = self.graph_generator._clean_filename(target_id)
        graph_path = self.graph_generator.generate(unique, target_id, ts)
        
        if progress_callback:
            progress_callback(95, "Generating validation report")


        

        filtered_items = []
        for x in unique:
            conf = x.get('confidence', 0)
            try:
                if int(conf) >= 50:
                    filtered_items.append(x)
            except:
                if str(conf) in ['High', 'Medium', '100%']:
                    filtered_items.append(x)
        
        filtered_graph_path = self.graph_generator.generate(filtered_items, f"{target_id}_filtered", ts)

        if progress_callback:
            progress_callback(100, "Complete")


        
        logger.info(f"Investigation complete: {len(unique)} findings from {len(queries)} queries")
        

        if graph_path:
            report['graph_path'] = graph_path
        if filtered_graph_path:
            report['filtered_graph_path'] = filtered_graph_path
            
        report['filtered_findings'] = filtered_items
            
        return report


if PYQT6_AVAILABLE:
    DARK_THEME = """
    QMainWindow, QDialog, QWidget {
        background-color: #000000;
        color: #e0e0e0;
        font-family: 'Segoe UI', 'Roboto', sans-serif;
    }
    QGroupBox {
        border: 1px solid #333;
        border-radius: 6px;
        margin-top: 12px;
        padding-top: 15px;
        background-color: #000000;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 5px;
        color: #1B7E74;
        font-weight: bold;
    }
    QLineEdit, QSpinBox, QComboBox, QTextEdit {
        background-color: #0d0d0d;
        border: 1px solid #333;
        border-radius: 4px;
        padding: 5px;
        color: #e0e0e0;
    }
    QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTextEdit:focus {
        border: 1px solid #1B7E74;
        background-color: #121212;
    }
    QPushButton {
        background-color: #1B7E74;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 8px 16px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #26a69a;
    }
    QPushButton:pressed {
        background-color: #004d40;
    }
    QPushButton:disabled {
        background-color: #222;
        color: #555;
    }
    QTableWidget {
        background-color: #000000;
        alternate-background-color: #0f0f0f;
        gridline-color: #222;
        border: 1px solid #333;
        selection-background-color: #1B7E74;
        selection-color: white;
    }
    QTableWidget::item {
        padding: 5px;
        border-bottom: 1px solid #1a1a1a;
    }
    QHeaderView::section {
        background-color: #0d0d0d;
        color: #e0e0e0;
        padding: 8px;
        border: 1px solid #333;
        font-weight: normal; 
    }
    QTabWidget::pane {
        border: 1px solid #333;
        background-color: #000000;
    }
    QTabBar::tab {
        background-color: #0d0d0d;
        color: #888;
        padding: 8px 16px;
        border: 1px solid #333;
        border-bottom: none;
    }
    QTabBar::tab:selected {
        background-color: #1B7E74;
        color: white;
    }
    QProgressBar {
        border: 1px solid #333;
        text-align: center;
        background-color: #0d0d0d;
        color: #e0e0e0;
    }
    QProgressBar::chunk {
        background-color: #1B7E74;
    }
    QCheckBox {
        spacing: 5px;
    }
    QStatusBar {
        background-color: #0d0d0d;
        color: #888;
        border-top: 1px solid #333;
    }
    QMenuBar {
        background-color: #000000;
        border-bottom: 1px solid #222;
    }
    QMenuBar::item:selected {
        background-color: #1B7E74;
        color: white;
    }
    QMenu {
        background-color: #121212;
        border: 1px solid #333;
    }
    QMenu::item:selected {
        background-color: #1B7E74;
    }
    """
    
    LIGHT_THEME = """
    QMainWindow, QDialog, QWidget {
        background-color: #f5f5f5;
        color: #000000;
        font-family: 'Segoe UI', 'Roboto', sans-serif;
    }
    QGroupBox {
        border: 1px solid #999;
        border-radius: 6px;
        margin-top: 12px;
        padding-top: 15px;
        background-color: #ffffff;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 5px;
        color: #00695c;
        font-weight: bold;
    }
    QLineEdit, QSpinBox, QComboBox, QTextEdit {
        background-color: #ffffff;
        border: 1px solid #888;
        border-radius: 4px;
        padding: 5px;
        color: #000000;
    }
    QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTextEdit:focus {
        border: 2px solid #00695c;
    }
    QPushButton {
        background-color: #00695c;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 8px 16px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #004d40;
    }
    QPushButton:pressed {
        background-color: #00251a;
    }
    QPushButton:disabled {
        background-color: #ccc;
        color: #666;
    }
    QTableWidget {
        background-color: white;
        alternate-background-color: #f0f0f0;
        gridline-color: #ccc;
        border: 1px solid #999;
        selection-background-color: #b2dfdb;
        selection-color: #000000;
    }
    QTableWidget::item {
        padding: 5px;
        border-bottom: 1px solid #e0e0e0;
    }
    QHeaderView::section {
        background-color: #f1f5f9;
        color: #475569;
        padding: 8px;
        border: 1px solid #d1d5db;
        font-weight: normal; 
    }
    QTabWidget::pane {
        border: 1px solid #999;
        background-color: white;
    }
    QTabBar::tab {
        background-color: #e0e0e0;
        color: #333;
        padding: 8px 16px;
        border: 1px solid #999;
        border-bottom: none;
    }
    QTabBar::tab:selected {
        background-color: #00695c;
        color: white;
    }
    QProgressBar {
        border: 1px solid #999;
        text-align: center;
        background-color: white;
        color: #000000;
    }
    QProgressBar::chunk {
        background-color: #00695c;
    }
    QCheckBox {
        color: #000000;
    }
    QLabel {
        color: #000000;
    }
    QStatusBar {
        background-color: #e0e0e0;
        color: #000000;
        border-top: 1px solid #999;
    }
    QMenuBar {
        background-color: #f5f5f5;
        border-bottom: 1px solid #999;
    }
    QMenuBar::item:selected {
        background-color: #00695c;
        color: white;
    }
    QMenu {
        background-color: white;
        border: 1px solid #999;
        color: #000000;
    }
    QMenu::item:selected {
        background-color: #b2dfdb;
        color: #000000;
    }
    """
    
    def create_status_icon(icon_type):

        pixmap = QPixmap(16, 16)
        pixmap.fill(Qt.GlobalColor.transparent)
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        if icon_type == "ready":
            painter.setPen(QPen(QColor(76, 175, 80), 2))
            painter.drawEllipse(2, 2, 12, 12)
        elif icon_type == "running":
            painter.setPen(QPen(QColor(33, 150, 243), 2))
            painter.drawEllipse(2, 2, 12, 12)
        elif icon_type == "error":
            painter.setPen(QPen(QColor(244, 67, 54), 2))
            painter.drawLine(4, 4, 12, 12)
            painter.drawLine(12, 4, 4, 12)
        elif icon_type == "complete":
            painter.setPen(QPen(QColor(76, 175, 80), 2))
            painter.drawLine(4, 8, 7, 11)
            painter.drawLine(7, 11, 12, 5)
        
        painter.end()
        return QIcon(pixmap)
    
    class AboutDialog(QDialog):

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("About OSINT Profiler")
            self.setFixedSize(500, 400)

            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
            self._init_ui()
        
        def _init_ui(self):
            layout = QVBoxLayout(self)
            layout.setSpacing(15)
            
            title_layout = QHBoxLayout()
            
            icon_label = QLabel()
            icon_label.setPixmap(self.parent().windowIcon().pixmap(64, 64))
            title_layout.addWidget(icon_label)
            
            title_text = QVBoxLayout()
            app_title = QLabel("<h1>OSINT Profiler</h1>")
            app_title.setTextFormat(Qt.TextFormat.RichText)
            title_text.addWidget(app_title)
            
            version = QLabel("<b>Version 1.0</b>")
            version.setTextFormat(Qt.TextFormat.RichText)
            title_text.addWidget(version)
            
            title_layout.addLayout(title_text)
            title_layout.addStretch()
            
            layout.addLayout(title_layout)
            
            desc = QLabel(
                "<p>A comprehensive Open Source Intelligence (OSINT) investigation tool "
                "for gathering and analyzing publicly available information.</p>"
            )
            desc.setWordWrap(True)
            desc.setTextFormat(Qt.TextFormat.RichText)
            layout.addWidget(desc)
            
            features_group = QGroupBox("Features")
            features_layout = QVBoxLayout()
            
            features = [
                "✓ Forensic-grade username variant generation",
                "✓ Multi-platform username search",
                "✓ Email address investigation",
                "✓ Phone number lookup",
                "✓ Advanced web search with variants",
                "✓ Confidence scoring & spam filtering",
                "✓ Anomaly detection",
                "✓ Multiple report formats (JSON, TXT, HTML, PDF)",
                "✓ Customizable reporting",
                "✓ Dark/Light theme support"
            ]
            
            for feature in features:
                label = QLabel(feature)
                features_layout.addWidget(label)
            
            features_group.setLayout(features_layout)
            layout.addWidget(features_group)
            
            info = QLabel(
                "<p><small><b>Disclaimer:</b> This tool is for educational and legitimate "
                "investigation purposes only. Users must comply with all applicable laws and "
                "respect privacy rights.</small></p>"
            )
            info.setWordWrap(True)
            info.setTextFormat(Qt.TextFormat.RichText)
            layout.addWidget(info)
            
            copyright_label = QLabel(
                "<p style='text-align:center;'><small>© 2026 OSINT Profiler v1.0<br/>"
                "Licensed under MIT License</small></p>"
            )
            copyright_label.setTextFormat(Qt.TextFormat.RichText)
            copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(copyright_label)
            
            layout.addStretch()
            
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(self.accept)
            layout.addWidget(close_btn)
    
    class ExportWorker(QThread):
        finished_sig = pyqtSignal(list, str)
        progress_sig = pyqtSignal(int, str)
        
        def __init__(self, engine, report, chosen, folder, base_name, report_config, categorize=False):
            super().__init__()
            self.engine = engine
            self.report = report
            self.chosen = chosen
            self.folder = folder
            self.base_name = base_name
            self.report_config = report_config
            self.categorize = categorize
            self._is_running = True
        
        def run(self):
            paths = []
            err = ""
            try:

                original_output_dir = self.engine.report_generator.output_dir
                self.engine.report_generator.output_dir = self.folder
                
                total = len(self.chosen)
                for idx, fmt in enumerate(self.chosen, 1):
                    if not self._is_running:
                        break
                    
                    self.progress_sig.emit(int((idx-1)/total*100), f"Generating {fmt}...")
                    
                    fname = f"{self.base_name}.{fmt.lower()}"
                    p = None
                    
                    try:
                        if fmt == "JSON":
                            p = self.engine.report_generator.generate_json(self.report, fname, self.report_config, self.categorize)
                        elif fmt == "TXT":
                            p = self.engine.report_generator.generate_txt(self.report, fname, self.report_config, self.categorize)
                        elif fmt == "HTML":
                            p = self.engine.report_generator.generate_html(self.report, fname, self.report_config, self.categorize)
                        elif fmt == "PDF":
                            p = self.engine.report_generator.generate_pdf(self.report, fname, self.report_config, self.categorize)
                        
                        if p:

                            if os.path.exists(p) and os.path.getsize(p) > 0:
                                paths.append(p)
                                self.progress_sig.emit(int(idx/total*100), f"Exported {fmt}")
                            else:
                                logger.warning(f"File {p} was not created or is empty")
                        
                    except Exception as e:
                        logger.error(f"Failed to generate {fmt}: {e}")

                        continue
                

                self.engine.report_generator.output_dir = original_output_dir
                
                if paths:
                    self.finished_sig.emit(paths, "")
                else:
                    self.finished_sig.emit([], "No files were generated successfully")
                    
            except Exception as e:
                logger.exception("Export failed")
                self.finished_sig.emit([], str(e))
        
        def stop(self):
            self._is_running = False

    class WorkerThread(QThread):
        progress = pyqtSignal(int, str)
        finished = pyqtSignal(dict)
        error = pyqtSignal(str)
        
        def __init__(self, engine, params):
            super().__init__()
            self.engine = engine
            self.params = params
            self._is_running = True
        
        def run(self):
            try:
                rep = self.engine.investigate(
                    email=self.params.get('email'),
                    phone=self.params.get('phone'),
                    username=self.params.get('username'),
                    country_code=self.params.get('country_code'),
                    max_search=self.params.get('max_search',30),
                    progress_callback=self._progress_cb
                )
                if self._is_running:
                    self.finished.emit(rep)
            except Exception as e:
                if self._is_running:
                    self.error.emit(str(e) + "\n" + traceback.format_exc())
        
        def _progress_cb(self, p, m):
            if self._is_running:
                self.progress.emit(int(p), str(m))
        
        def stop(self):
            self._is_running = False

    class AboutDialog(QDialog):

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("About OSINT Profiler")
            self.setFixedSize(500, 520)
            self.setFixedSize(500, 520)
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
            self._init_ui()
        
        def _init_ui(self):
            layout = QVBoxLayout(self)
            layout.setSpacing(10)
            layout.setContentsMargins(30, 30, 30, 30)
            

            icon_label = QLabel()
            if self.parent():
                icon_label.setPixmap(self.parent().windowIcon().pixmap(80, 80))
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(icon_label)
            

            app_title = QLabel("<h1>OSINT Profiler</h1>")
            app_title.setTextFormat(Qt.TextFormat.RichText)
            app_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(app_title)
            

            version = QLabel("<b>Version 1.0</b>")
            version.setTextFormat(Qt.TextFormat.RichText)
            version.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(version)
            
            layout.addSpacing(10)
            

            desc = QLabel(
                "A comprehensive Open Source Intelligence (OSINT) investigation tool "
                "for gathering and analyzing publicly available information."
            )
            desc.setWordWrap(True)
            desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(desc)
            
            layout.addSpacing(10)
            

            features_label = QLabel("<b>Key Features:</b>")
            features_label.setTextFormat(Qt.TextFormat.RichText)
            features_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(features_label)
            
            features_text = (
                "• Forensic-grade username variant generation\n"
                "• Multi-platform username search\n"
                "• Email investigation\n"
                "• Phone investigation\n"
                "• Advanced web search with variants\n"
                "• Confidence scoring & Anomaly detection"
            )
            features = QLabel(features_text)
            features.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(features)
            
            layout.addSpacing(20)
            

            disclaimer = QLabel(
                "<span style='color: #888; font-size: 10px;'>Disclaimer: This tool is for educational and legitimate "
                "investigation purposes only. Users must comply with applicable laws.</span>"
            )
            disclaimer.setWordWrap(True)
            disclaimer.setTextFormat(Qt.TextFormat.RichText)
            disclaimer.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(disclaimer)
            
            layout.addStretch()
            

            copyright_label = QLabel(
                "<span style='color: #666; font-size: 10px;'>© 2026 OSINT Profiler v1.0<br/>"
                "Licensed under MIT License</span>"
            )
            copyright_label.setTextFormat(Qt.TextFormat.RichText)
            copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(copyright_label)
            

            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            close_btn = QPushButton("Close")
            close_btn.setFixedWidth(100)
            close_btn.clicked.connect(self.accept)
            btn_layout.addWidget(close_btn)
            btn_layout.addStretch()
            layout.addLayout(btn_layout)

    class ReportConfigDialog(QDialog):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Report Configuration")
            self.resize(600, 700)
            self.report_config = DEFAULT_REPORT_CONFIG.copy()
            self._init_ui()
        
        def _init_ui(self):
            layout = QVBoxLayout(self)
            tabs = QTabWidget()
            

            basic_tab = QWidget()
            basic_layout = QFormLayout(basic_tab)
            

            self.timezone_combo = QComboBox()
            for tz_code, tz_name in TIME_ZONES:
                self.timezone_combo.addItem(f"{tz_code} - {tz_name}", tz_code)
            

            current_tz = self.report_config.get('timezone', 'UTC')
            tz_index = self.timezone_combo.findData(current_tz)
            if tz_index >= 0:
                self.timezone_combo.setCurrentIndex(tz_index)
            else:
                self.timezone_combo.setCurrentText("UTC - UTC")
            basic_layout.addRow("Time Zone:", self.timezone_combo)
            

            self.page_size_combo = QComboBox()
            for size_code, size_name in PAGE_SIZES:
                self.page_size_combo.addItem(size_name, size_code)
            

            current_page_size = self.report_config.get('page_size', 'A4')
            page_size_index = self.page_size_combo.findData(current_page_size)
            if page_size_index >= 0:
                self.page_size_combo.setCurrentIndex(page_size_index)
            else:
                self.page_size_combo.setCurrentText("A4 (210x297mm)")
            basic_layout.addRow("Page Size:", self.page_size_combo)
            

            self.quality_combo = QComboBox()
            for quality_code, quality_name in QUALITY_LEVELS:
                self.quality_combo.addItem(quality_name, quality_code)
            

            current_quality = self.report_config.get('quality', 'standard')
            quality_index = self.quality_combo.findData(current_quality)
            if quality_index >= 0:
                self.quality_combo.setCurrentIndex(quality_index)
            else:
                self.quality_combo.setCurrentText("Standard")
            basic_layout.addRow("Quality:", self.quality_combo)
            

            self.title_edit = QLineEdit(self.report_config.get('report_title', 'OSINT Investigation Report'))
            basic_layout.addRow("Report Title:", self.title_edit)
            

            self.company_edit = QLineEdit(self.report_config.get('company_name', 'OSINT Profiler'))
            basic_layout.addRow("Company:", self.company_edit)
            
            tabs.addTab(basic_tab, "Basic")
            

            font_tab = QWidget()
            font_layout = QFormLayout(font_tab)
            

            self.font_combo = QComboBox()
            try:
                font_db = QFontDatabase()
                families = font_db.families()

                unique_families = sorted(set(str(f) for f in families))
                for family in unique_families:
                    self.font_combo.addItem(family)
            except Exception:

                for family in ['Helvetica', 'Arial', 'Times New Roman', 'Courier New', 'Verdana', 'Georgia']:
                    self.font_combo.addItem(family)
            

            current_font = self.report_config.get('font_family', 'Helvetica')
            font_index = self.font_combo.findText(current_font)
            if font_index >= 0:
                self.font_combo.setCurrentIndex(font_index)
            else:

                if 'helvetica' in current_font.lower():
                    helvetica_index = self.font_combo.findText('Helvetica')
                    if helvetica_index >= 0:
                        self.font_combo.setCurrentIndex(helvetica_index)
            
            font_layout.addRow("Font Family:", self.font_combo)
            

            self.font_size_spin = QSpinBox()
            self.font_size_spin.setRange(6, 24)
            self.font_size_spin.setValue(self.report_config.get('font_size', 10))
            font_layout.addRow("Font Size:", self.font_size_spin)
            

            self.title_size_spin = QSpinBox()
            self.title_size_spin.setRange(10, 36)
            self.title_size_spin.setValue(self.report_config.get('title_font_size', 16))
            font_layout.addRow("Title Size:", self.title_size_spin)
            

            self.heading_size_spin = QSpinBox()
            self.heading_size_spin.setRange(8, 24)
            self.heading_size_spin.setValue(self.report_config.get('heading_font_size', 14))
            font_layout.addRow("Heading Size:", self.heading_size_spin)
            
            tabs.addTab(font_tab, "Font")
            

            content_tab = QWidget()
            content_layout = QVBoxLayout(content_tab)
            

            section_group = QGroupBox("Report Sections")
            section_layout = QVBoxLayout()
            self.section_checks = {}
            

            current_sections = set(self.report_config.get('sections', ['summary', 'findings', 'anomalies', 'statistics']))
            
            for section_code, section_name in UI_VISIBLE_SECTIONS:
                cb = QCheckBox(section_name)
                cb.setChecked(section_code in current_sections)
                section_layout.addWidget(cb)
                self.section_checks[section_code] = cb
            
            section_group.setLayout(section_layout)
            content_layout.addWidget(section_group)
            

            options_group = QGroupBox("Options")
            options_layout = QFormLayout()
            
            self.show_conf_colors = QCheckBox("Show confidence colors")
            self.show_conf_colors.setChecked(self.report_config.get('show_confidence_colors', True))
            options_layout.addRow(self.show_conf_colors)
            
            self.include_previews = QCheckBox("Include previews")
            self.include_previews.setChecked(self.report_config.get('include_previews', True))
            options_layout.addRow(self.include_previews)
            
            self.group_by_conf = QCheckBox("Group by confidence")
            self.group_by_conf.setChecked(self.report_config.get('group_by_confidence', False))
            options_layout.addRow(self.group_by_conf)
            
            self.preview_length_spin = QSpinBox()
            self.preview_length_spin.setRange(50, 1000)
            self.preview_length_spin.setValue(self.report_config.get('max_preview_length', 300))
            options_layout.addRow("Max Preview Length:", self.preview_length_spin)
            

            self.compress_pdf = QCheckBox("Compress PDF (smaller file size)")
            self.compress_pdf.setChecked(self.report_config.get('compress_pdf', False))
            options_layout.addRow(self.compress_pdf)
            
            options_group.setLayout(options_layout)
            content_layout.addWidget(options_group)
            
            tabs.addTab(content_tab, "Content")
            
            layout.addWidget(tabs)
            

            button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            button_box.accepted.connect(self.accept)
            button_box.rejected.connect(self.reject)
            layout.addWidget(button_box)
        
        def get_config(self):

            config = DEFAULT_REPORT_CONFIG.copy()
            

            config['timezone'] = self.timezone_combo.currentData()
            config['page_size'] = self.page_size_combo.currentData()
            config['quality'] = self.quality_combo.currentData()
            config['report_title'] = self.title_edit.text()
            config['company_name'] = self.company_edit.text()
            
            config['font_family'] = self.font_combo.currentText()
            config['font_size'] = self.font_size_spin.value()
            config['title_font_size'] = self.title_size_spin.value()
            config['heading_font_size'] = self.heading_size_spin.value()
            

            sections = []
            for section_code, cb in self.section_checks.items():
                if cb.isChecked():
                    sections.append(section_code)
            config['sections'] = sections
            

            config['show_confidence_colors'] = self.show_conf_colors.isChecked()
            config['include_previews'] = self.include_previews.isChecked()
            config['group_by_confidence'] = self.group_by_conf.isChecked()
            config['max_preview_length'] = self.preview_length_spin.value()
            config['compress_pdf'] = self.compress_pdf.isChecked()
            
            return config

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("OSINT Profiler v1.0")
            self.resize(1200, 800)

            self.dark_mode = True

            icon = create_app_icon(64, self.dark_mode)
            if icon:
                self.setWindowIcon(icon)

            self.engine = OSINTEngine()
            self.current_report = None
            self.current_report_config = DEFAULT_REPORT_CONFIG.copy()
            self.worker = None
            self.export_worker = None
            
            self._build_ui()
            self._setup_connections()
            self._setup_menu()
            self._setup_statusbar()
            self._apply_theme()

        def _build_ui(self):
            central = QWidget()
            self.setCentralWidget(central)
            layout = QVBoxLayout(central)


            top_widget = QWidget()
            top_layout = QHBoxLayout(top_widget)
            
            input_group = QGroupBox("Investigation Parameters")
            input_form = QFormLayout()
            

            self.email_input = QLineEdit()
            self.email_input.setPlaceholderText("Email address")
            self.email_input.setToolTip("Enter an email address to investigate (e.g., john.doe@example.com)")
            input_form.addRow("Email:", self.email_input)
            

            self.username_input = QLineEdit()
            self.username_input.setPlaceholderText("Username")
            self.username_input.setToolTip("Enter a username to investigate (e.g., johndoe, john.doe)")
            input_form.addRow("Username:", self.username_input)
            

            phone_widget = QWidget()
            phone_layout = QHBoxLayout(phone_widget)
            phone_layout.setContentsMargins(0, 0, 0, 0)
            phone_layout.setSpacing(10)
            

            self.country_code_combo = QComboBox()
            self.country_code_combo.setEditable(True)
            self.country_code_combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
            self.country_code_combo.setSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
            self.country_code_combo.setMinimumWidth(180)
            self.country_code_combo.setMaximumWidth(220)
            self.country_code_combo.setToolTip("Select or type country code (e.g., '1' for USA, '91' for India, '44' for UK)\nType country name to search")
            

            self.filter_checkbox = QCheckBox("Filter Low Confidence")
            self.filter_checkbox.setChecked(False)
            self.filter_checkbox.setToolTip("Check to hide low confidence and irrelevant results")
            self.filter_checkbox.stateChanged.connect(self.toggle_result_filter)
            

            for code, description in COUNTRY_CODES:
                if code == '':
                    self.country_code_combo.addItem(f"{description}", code)
                else:
                    self.country_code_combo.addItem(f"+{code} - {description}", code)
            

            self.country_code_combo.lineEdit().setPlaceholderText("Auto-detect")
            

            self.country_code_combo.setCurrentIndex(-1)
            

            self.phone_input = QLineEdit()
            self.phone_input.setPlaceholderText("Phone number")
            self.phone_input.setMinimumWidth(200)
            self.phone_input.setToolTip("Enter phone number (e.g., 1234567890)\nInclude country code if not selected above")
            
            phone_layout.addWidget(self.country_code_combo)
            phone_layout.addWidget(self.phone_input)
            
            input_form.addRow("Phone:", phone_widget)
            
            self.truecaller_input = QLineEdit()
            self.truecaller_input.setPlaceholderText("Truecaller Auth-ID (Optional)")
            self.truecaller_input.setToolTip("Enter your truecallerpy installation ID for name extraction")
            input_form.addRow("Truecaller ID:", self.truecaller_input)
            
            self.proxy_input = QLineEdit()
            self.proxy_input.setPlaceholderText("http://user:pass@ip:port (Optional)")
            self.proxy_input.setToolTip("Proxy URL for DuckDuckGo queries")
            input_form.addRow("Proxy:", self.proxy_input)

            input_form.addRow("Filter:", self.filter_checkbox)

            self.deep_scan_checkbox = QCheckBox("Deep Scan")
            self.deep_scan_checkbox.setChecked(False)
            self.deep_scan_checkbox.setToolTip("Check to bypass query limits (extremely thorough but slower)")
            input_form.addRow("Mode:", self.deep_scan_checkbox)
            
            input_group.setLayout(input_form)
            top_layout.addWidget(input_group, 2)
            

            config_group = QGroupBox("Report Configuration")
            config_layout = QVBoxLayout()
            self.config_preview = QTextEdit()
            self.config_preview.setReadOnly(True)
            self.config_preview.setMaximumHeight(150)
            self.config_preview.setPlainText(self._get_config_preview())
            config_layout.addWidget(self.config_preview)
            
            config_btn_layout = QHBoxLayout()
            self.config_btn = QPushButton("Configure Report...")
            self.config_btn.clicked.connect(self.configure_report)
            config_btn_layout.addWidget(self.config_btn)
            config_btn_layout.addStretch()
            config_layout.addLayout(config_btn_layout)
            
            config_group.setLayout(config_layout)
            top_layout.addWidget(config_group, 1)
            
            layout.addWidget(top_widget)


            btn_h = QHBoxLayout()
            self.run_btn = QPushButton("Start Investigation")
            self.run_btn.setToolTip("Start the investigation with the provided parameters")
            self.stop_btn = QPushButton("Stop")
            self.stop_btn.setEnabled(False)
            self.stop_btn.setToolTip("Stop the current investigation")
            self.stop_btn.setToolTip("Stop the current investigation")
            self.export_btn = QPushButton("Export Report")
            self.export_btn.setEnabled(False)
            self.export_btn.setToolTip("Export investigation results to file(s)")
            self.export_btn.setToolTip("Export investigation results to file(s)")
            
            self.graph_btn = QPushButton("View Graph")
            self.graph_btn.setEnabled(False)
            self.graph_btn.setToolTip("Open interactive investigation graph")
            self.graph_btn.clicked.connect(self.open_latest_graph)
            self.graph_btn.setCursor(Qt.CursorShape.PointingHandCursor)

            self.cancel_export_btn = QPushButton("Cancel Export")
            self.cancel_export_btn.setEnabled(False)
            self.cancel_export_btn.setVisible(False)
            self.cancel_export_btn.setToolTip("Cancel the current export process")
            
            btn_h.addWidget(self.run_btn)
            btn_h.addWidget(self.stop_btn)
            btn_h.addWidget(self.export_btn)
            btn_h.addWidget(self.graph_btn)
            btn_h.addWidget(self.cancel_export_btn)
            btn_h.addStretch()
            layout.addLayout(btn_h)


            self.progress = QProgressBar()
            self.progress.setVisible(False)
            self.progress.setToolTip("Investigation progress")
            layout.addWidget(self.progress)


            self.tabs = QTabWidget()
            

            self.results_table = QTableWidget(0, 6)
            self.results_table.setHorizontalHeaderLabels(["Platform", "URL", "Confidence", "Preview", "Found", "Type"])
            self.results_table.horizontalHeader().setStretchLastSection(True)
            hdr = self.results_table.horizontalHeader()
            hdr.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
            hdr.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.Stretch)
            hdr.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
            self.results_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
            self.results_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.results_table.cellDoubleClicked.connect(self.open_url_from_table)
            self.results_table.setToolTip("Double-click on URL to open in browser")
            self.tabs.addTab(self.results_table, "Results")
            

            self.summary_text = QTextEdit()
            self.summary_text.setReadOnly(True)
            self.tabs.addTab(self.summary_text, "Summary")
            

            self.stats_text = QTextEdit()
            self.stats_text.setReadOnly(True)
            self.tabs.addTab(self.stats_text, "Statistics")
            
            layout.addWidget(self.tabs)

        def _setup_menu(self):
            menubar = self.menuBar()
            
            file_menu = menubar.addMenu("&File")
            
            export_action = QAction("&Export Report...   ", self)
            export_action.setShortcut("Ctrl+E")
            export_action.triggered.connect(self.export_report)
            file_menu.addAction(export_action)
            
            file_menu.addSeparator()
            
            exit_action = QAction("E&xit", self)
            exit_action.setShortcut("Ctrl+Q")
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)
            
            view_menu = menubar.addMenu("&View")
            

            self.theme_action = QAction("&Dark Mode", self, checkable=True)
            self.theme_action.setShortcut("Ctrl+D")
            self.theme_action.setChecked(self.dark_mode) 
            self.theme_action.triggered.connect(self.toggle_theme_menu)
            view_menu.addAction(self.theme_action)
            
            help_menu = menubar.addMenu("&Help")
            
            about_action = QAction("&About", self)
            about_action.triggered.connect(self.show_about)
            help_menu.addAction(about_action)
        
        def _setup_statusbar(self):
            self.status_bar = QStatusBar()
            self.setStatusBar(self.status_bar)
            

            self.status_icon_label = QLabel()
            self.status_icon_label.setPixmap(create_status_icon("ready").pixmap(16, 16))
            self.status_bar.addWidget(self.status_icon_label)
            
            self.status_label = QLabel("Ready")
            self.status_label.setStyleSheet("padding-left: 5px; font-weight: bold;")
            self.status_bar.addWidget(self.status_label)
            
            self.status_bar.addWidget(QLabel(""), 1)
            

            self.theme_checkbox = QCheckBox("Dark Mode")
            self.theme_checkbox.setChecked(True)
            self.theme_checkbox.toggled.connect(self.toggle_theme_checkbox)
            self.theme_checkbox.setCursor(Qt.CursorShape.PointingHandCursor)
            self.theme_checkbox.setStyleSheet("margin-right: 15px;")
            self.status_bar.addPermanentWidget(self.theme_checkbox)
        
        def _apply_theme(self):
            if self.dark_mode:
                self.setStyleSheet(DARK_THEME)
                self.theme_checkbox.setText("Dark Mode")
                self.theme_checkbox.setChecked(True)
                self.theme_action.setChecked(True)
            else:
                self.setStyleSheet(LIGHT_THEME)
                self.theme_checkbox.setText("Light Mode")
                self.theme_checkbox.setChecked(False)
                self.theme_action.setChecked(False)
        
        def toggle_theme(self):
            self.dark_mode = not self.dark_mode
            self._apply_theme()
            
        def toggle_theme_checkbox(self, checked):
            self.dark_mode = checked
            self._apply_theme()

        def toggle_theme_menu(self, checked):
            self.dark_mode = checked
            self._apply_theme()
        
        def show_about(self):
            dialog = AboutDialog(self)
            dialog.exec()
        
        def update_status(self, message, icon_type="ready"):
            self.status_label.setText(message)
            self.status_icon_label.setPixmap(create_status_icon(icon_type).pixmap(16, 16))

        def _setup_connections(self):
            self.run_btn.clicked.connect(self.start_investigation)
            self.stop_btn.clicked.connect(self.stop_investigation)
            self.export_btn.clicked.connect(self.export_report)
            self.cancel_export_btn.clicked.connect(self.cancel_export)

        def _get_config_preview(self):
            config = self.current_report_config
            sections = config.get('sections', [])
            sections_display = [name for code, name in REPORT_SECTIONS if code in sections]
            
            preview = f"""Font: {config['font_family']} ({config['font_size']}pt)
Timezone: {config['timezone']}
Page Size: {config['page_size']}
Quality: {config['quality']}
Sections: {', '.join(sections_display)}
Include Previews: {'Yes' if config.get('include_previews', True) else 'No'}"""
            return preview

        def configure_report(self):
            dialog = ReportConfigDialog(self)
            dialog.report_config = self.current_report_config.copy()
            
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.current_report_config = dialog.get_config()
                self.config_preview.setPlainText(self._get_config_preview())
                QMessageBox.information(self, "Configuration Saved", "Report configuration has been updated.")

        def start_investigation(self):
            email = self.email_input.text().strip() or None
            phone = self.phone_input.text().strip() or None
            username = self.username_input.text().strip() or None
            
            truecaller_id = self.truecaller_input.text().strip() or None
            proxy = self.proxy_input.text().strip() or None
            
            country_code = None
            country_code_data = self.country_code_combo.currentData()
            if country_code_data and country_code_data != '':
                country_code = country_code_data
                logger.info(f"Using country code: +{country_code}")
            else:
                logger.info("Using auto-detect for phone number")
            
            if not any([email, phone, username]):
                QMessageBox.warning(self, "Input required", "Enter at least one of email, phone, username.")
                return
            

            if self.export_worker and self.export_worker.isRunning():
                reply = QMessageBox.question(self, "Export in Progress", 
                                           "An export is currently in progress. Cancel it and start investigation?",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.No:
                    return
                self.cancel_export()
            

            self.results_table.setRowCount(0)
            self.summary_text.clear()
            self.stats_text.clear()
            

            self.progress.setVisible(True)
            self.progress.setValue(0)
            self.run_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.export_btn.setEnabled(False)
            self.config_btn.setEnabled(False)
            self.update_status("Starting investigation...", "running")
            
            params = {
                'email': email,
                'phone': phone,
                'username': username,
                'country_code': country_code,
                'max_search': 50,
                'proxy': proxy,
                'truecaller_id': truecaller_id,
                'deep_scan': self.deep_scan_checkbox.isChecked()
            }
            
            # Instantiate a fresh engine to use the newest proxy/truecaller/deep config
            self.engine = OSINTEngine(proxy=proxy, truecaller_id=truecaller_id, deep_scan=params['deep_scan'])
            
            self.worker = WorkerThread(self.engine, params)
            self.worker.progress.connect(self.on_progress)
            self.worker.finished.connect(self.on_finished)
            self.worker.error.connect(self.on_error)
            self.worker.start()

        def stop_investigation(self):
            if self.worker and self.worker.isRunning():
                self.worker.stop()
                self.status_label.setText("Investigation stopped")
                self.run_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                self.config_btn.setEnabled(True)

        def on_progress(self, p, m):
            self.progress.setValue(p)
            self.status_label.setText(m)

        def on_finished(self, report):
            self.current_report = report
            self.progress.setValue(100)
            self.status_label.setText(f"Complete! Found {len(report.get('findings',[]))} relevant results.")
            self.run_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.export_btn.setEnabled(True)
            self.config_btn.setEnabled(True)
            

            if report.get('graph_path'):
                self.graph_btn.setEnabled(True)
                
            self.display_report(report)
            

            self.toggle_result_filter(self.filter_checkbox.checkState())

        def toggle_result_filter(self, state):
            if not self.current_report:
                return
                
            if state == Qt.CheckState.Checked.value:

                findings = self.current_report.get('filtered_findings', [])
                if not findings:
                     all_findings = self.current_report.get('findings', [])
                     
                     findings = []
                     for f in all_findings:
                         try:
                             if int(f.get('confidence', 0)) >= 50:
                                 findings.append(f)
                         except:
                             if f.get('confidence') in ['High', 'Medium']:
                                 findings.append(f)
                

                self._update_table_with_findings(findings)
                self.status_label.setText(f"Showing {len(findings)} filtered results (High/Medium Confidence)")
            else:

                findings = self.current_report.get('findings', [])
                self._update_table_with_findings(findings)
                self.status_label.setText(f"Showing all {len(findings)} results")

        def _update_table_with_findings(self, findings):
            self.results_table.setRowCount(0)
            self.results_table.setRowCount(len(findings))
            

            phone_intel = None
            for f in findings:
                if f.get('type') == 'phone_intelligence' and 'intelligence' in f:
                    phone_intel = f['intelligence']
                    break
            
            for i, f in enumerate(findings):
                platform = f.get('platform', '')
                if f.get('type') == 'phone_intelligence':
                    platform = "Phone Intelligence"
                
                self.results_table.setItem(i, 0, QTableWidgetItem(platform))
                self.results_table.setItem(i, 1, QTableWidgetItem(f.get('url', '')))
                

                conf = f.get('confidence', 'Unknown')

                conf_item = QTableWidgetItem(str(conf))
                if conf == 'High' or (isinstance(conf, (int, float)) and conf >= 80):
                    conf_item.setBackground(QColor(200, 230, 201) if not self.dark_mode else QColor(27, 94, 32))
                elif conf == 'Medium' or (isinstance(conf, (int, float)) and conf >= 50):
                    conf_item.setBackground(QColor(255, 224, 178) if not self.dark_mode else QColor(230, 81, 0))
                self.results_table.setItem(i, 2, conf_item)
                
                self.results_table.setItem(i, 3, QTableWidgetItem(f.get('snippet', '')))
                self.results_table.setItem(i, 4, QTableWidgetItem("Yes"))
                self.results_table.setItem(i, 5, QTableWidgetItem(f.get('type', 'web')))

        def open_latest_graph(self):
            if not self.current_report:
                return
            
            graph_file = self.current_report.get('graph_path')
            
            if graph_file and os.path.exists(graph_file):
                import webbrowser
                webbrowser.open(f'file:///{os.path.abspath(graph_file)}')
            else:
                QMessageBox.warning(self, "Graph Not Found", "No graph file found for this investigation.")



        def on_error(self, err):
            QMessageBox.critical(self, "Error", str(err))
            self.status_label.setText("Error occurred")
            self.run_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.config_btn.setEnabled(True)

        def display_report(self, report):

            all_findings = report.get('findings', [])
            high_conf = []
            other = []
            for f in all_findings:
                conf = f.get('confidence', 0)
                is_high = False
                try:
                    if f.get('type') == 'phone_intelligence':
                        is_high = True
                    elif int(conf) >= 50:
                        is_high = True
                except:
                   if str(conf) in ['High', 'Medium', '100%']:
                       is_high = True
                
                if is_high:
                    high_conf.append(f)
                else:
                    other.append(f)
            

            high_conf.sort(key=lambda x: x.get('confidence', 0) if isinstance(x.get('confidence', 0), (int, float)) else 0, reverse=True)
            other.sort(key=lambda x: x.get('confidence', 0) if isinstance(x.get('confidence', 0), (int, float)) else 0, reverse=True)
            
            sorted_findings = high_conf + other
            
            self.results_table.setRowCount(len(sorted_findings))
            

            phone_intel = None
            for f in sorted_findings:
                if f.get('type') == 'phone_intelligence' and 'intelligence' in f:
                    phone_intel = f['intelligence']
                    break
            
            for i, f in enumerate(sorted_findings):
                platform = f.get('platform', '')
                if f.get('type') == 'phone_intelligence':
                    platform = "Phone Intelligence"
                
                self.results_table.setItem(i, 0, QTableWidgetItem(platform))
                self.results_table.setItem(i, 1, QTableWidgetItem(f.get('url', '')))
                

                if f.get('type') == 'phone_intelligence':
                    self.results_table.setItem(i, 2, QTableWidgetItem("100%"))
                else:
                    conf_val = f.get('confidence', 0)
                    item = QTableWidgetItem(f"{conf_val}%")
                    
                    
                    try:
                        val = int(conf_val)
                        if val >= 80:
                            item.setBackground(QColor(200, 230, 201) if not self.dark_mode else QColor(27, 94, 32))
                        elif val >= 50:
                            item.setBackground(QColor(255, 249, 196) if not self.dark_mode else QColor(245, 127, 23))
                    except:
                        pass
                    
                    self.results_table.setItem(i, 2, item)
                

                if f.get('type') == 'phone_intelligence' and 'intelligence' in f:
                    intel = f['intelligence']
                    snippet = f"Country: {intel.get('country', 'Unknown')}, Carrier: {intel.get('carrier', 'Unknown')}, Type: {intel.get('line_type', 'Unknown')}"
                    self.results_table.setItem(i, 3, QTableWidgetItem(snippet))
                else:
                    self.results_table.setItem(i, 3, QTableWidgetItem(f.get('snippet', '')[:100]))
                
                ts = format_timestamp(f.get('timestamp', ''), self.current_report_config['timezone'], False)
                self.results_table.setItem(i, 4, QTableWidgetItem(ts))
                self.results_table.setItem(i, 5, QTableWidgetItem(f.get('type', '')))
            
            self.results_table.resizeColumnsToContents()
            
            params = report.get('parameters', {})
            stats = report.get('statistics', {})
            

            summary = "<h3>Investigation Summary</h3>"
            summary += "<table border='0' cellspacing='5'>"
            if params.get('email'):
                summary += f"<tr><td><b>Email:</b></td><td>{params['email']}</td></tr>"
            if params.get('phone'):
                summary += f"<tr><td><b>Phone:</b></td><td>{params['phone']}</td></tr>"
            if params.get('country_code'):
                summary += f"<tr><td><b>Country Code:</b></td><td>+{params['country_code']}</td></tr>"
            if params.get('username'):
                summary += f"<tr><td><b>Username:</b></td><td>{params['username']}</td></tr>"
            
            summary += f"<tr><td><b>Total Findings:</b></td><td>{len(all_findings)}</td></tr>"
            summary += f"<tr><td><b>Status:</b></td><td>Complete ({len(high_conf)} High Confidence)</td></tr>"
            summary += "</table>"
                

            if phone_intel and 'error' not in phone_intel:
                summary += "<h4>Phone Intelligence</h4>"
                summary += "<ul>"
                summary += f"<li><b>E.164:</b> {phone_intel.get('e164_format', 'N/A')}</li>"
                summary += f"<li><b>Country:</b> {phone_intel.get('country', 'Unknown')}</li>"
                summary += f"<li><b>Carrier:</b> {phone_intel.get('carrier', 'Unknown')}</li>"
                summary += f"<li><b>Line Type:</b> {phone_intel.get('line_type', 'Unknown')}</li>"
                summary += f"<li><b>Valid:</b> {'Yes' if phone_intel.get('valid') else 'No'}</li>"
                summary += "</ul>"

            self.summary_text.setHtml(summary)
            

            st = "<h3>Statistics</h3>"
            st += "<ul>"
            st += f"<li><b>Total Findings:</b> {len(all_findings)}</li>"
            st += f"<li><b>High Confidence:</b> {len(high_conf)}</li>"
            st += f"<li><b>Queries Executed:</b> {stats.get('queries_executed', 0)}</li>"
            st += f"<li><b>Average Confidence:</b> {stats.get('average_confidence', 0)}%</li>"
            

            st += "</ul><h4>Platform Distribution</h4><ul>"
            from collections import Counter
            platforms = Counter([f.get('platform','Unknown') for f in all_findings])
            for plat, cnt in platforms.most_common(5):
                st += f"<li><b>{plat}:</b> {cnt}</li>"
            st += "</ul>"
            
            self.stats_text.setHtml(st)

        def export_report(self):
            if not self.current_report:
                return
            

            dialog = QDialog(self)
            dialog.setWindowTitle("Export Report")
            layout = QVBoxLayout(dialog)
            

            format_group = QGroupBox("Select Formats")
            format_layout = QVBoxLayout()
            checks = {}
            for fmt in ["JSON", "TXT", "HTML", "PDF"]:
                cb = QCheckBox(fmt)
                cb.setChecked(True)
                format_layout.addWidget(cb)
                checks[fmt] = cb
            format_group.setLayout(format_layout)
            layout.addWidget(format_group)
            

            scope_group = QGroupBox("Export Scope")
            scope_layout = QVBoxLayout()
            scope_btn_group = QButtonGroup(dialog)
            
            radio_all = QRadioButton("All Results (Categorized)")
            radio_all.setChecked(True)
            radio_all.setToolTip("Export all findings. High/Medium confidence items will be listed first.")
            scope_layout.addWidget(radio_all)
            scope_btn_group.addButton(radio_all)
            
            radio_filtered = QRadioButton("High Confidence Only")
            radio_filtered.setToolTip("Export ONLY findings with High/Medium confidence.")
            scope_layout.addWidget(radio_filtered)
            scope_btn_group.addButton(radio_filtered)
            
            scope_group.setLayout(scope_layout)
            layout.addWidget(scope_group)
            

            btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            btns.accepted.connect(dialog.accept)
            btns.rejected.connect(dialog.reject)
            layout.addWidget(btns)
            
            if dialog.exec() == QDialog.DialogCode.Accepted:
                chosen = [fmt for fmt, cb in checks.items() if cb.isChecked()]
                if not chosen:
                    return
                

                folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
                if not folder:
                    return
                

                categorize = False
                report_to_export = self.current_report
                
                if radio_filtered.isChecked():

                    findings = self.current_report.get('findings', [])
                    high_conf = []
                    for f in findings:
                        conf = f.get('confidence', 0)
                        try:
                            if f.get('type') == 'phone_intelligence':
                                high_conf.append(f)
                                continue
                            
                            val = int(conf)
                            if val >= 50:
                                high_conf.append(f)
                        except:
                            if str(conf) in ['High', 'Medium', '100%']:
                                high_conf.append(f)
                    

                    report_to_export = self.current_report.copy()
                    report_to_export['findings'] = high_conf
                    categorize = False
                    
                else:

                    categorize = True
                

                params = report_to_export.get('parameters', {})
                base_name = build_report_basename(
                    email=params.get('email'),
                    phone=params.get('phone'),
                    username=params.get('username')
                )

                base_name = f"{base_name}_{int(time.time())}"
                

                self.export_progress = QProgressDialog("Exporting...", "Cancel", 0, 100, self)
                self.export_progress.setWindowModality(Qt.WindowModality.WindowModal)
                self.export_progress.setMinimumDuration(0)
                
                self.export_worker = ExportWorker(self.engine, report_to_export, chosen, folder, base_name, self.current_report_config, categorize)
                self.export_worker.progress_sig.connect(lambda p, m: self.export_progress.setValue(p))
                self.export_worker.progress_sig.connect(lambda p, m: self.export_progress.setLabelText(m))
                self.export_worker.finished_sig.connect(self.on_export_finished)
                
                self.export_progress.canceled.connect(self.export_worker.stop)
                self.export_worker.start()

        def on_export_progress(self, p, m):
            self.progress.setValue(p)
            self.update_status(m, "running")

        def on_export_finished(self, paths, error):
            if hasattr(self, 'export_progress'):
                self.export_progress.close()
            
            if error:
                QMessageBox.critical(self, "Export Failed", error)
            elif not paths:
                 QMessageBox.warning(self, "Export Warning", "No files were generated.")
            else:
                msg = "Export complete!\n\nFiles saved:\n" + "\n".join([os.path.basename(p) for p in paths])
                
                reply = QMessageBox.question(self, "Export Success", 
                                           msg + "\n\nDo you want to open the output folder?",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

                if reply == QMessageBox.StandardButton.Yes and paths:
                    try:
                        folder = os.path.dirname(paths[0])
                        os.startfile(folder)
                    except:
                        pass

        def cancel_export(self):
            if self.export_worker:
                self.export_worker.stop()
                self.update_status("Cancelling export...", "ready")

        def open_url_from_table(self, row, col):
            if col == 1:
                url = self.results_table.item(row, col).text()
                if url:
                    QDesktopServices.openUrl(QUrl(url))

        def closeEvent(self, event):
            try:
                if hasattr(self, "worker") and self.worker and self.worker.isRunning():
                    self.worker.stop()
            except:
                pass
            
            try:
                if hasattr(self, "export_worker") and self.export_worker and self.export_worker.isRunning():
                    self.export_worker.stop()
            except:
                pass
            

            if hasattr(self, "engine") and self.engine:
                pass

            event.accept()

def set_app_user_model_id():
    if sys.platform == 'win32':
        try:
            myappid = 'mycompany.osintprofiler.gui.1.0'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception:
            pass

def launch_gui():
    if not PYQT6_AVAILABLE:
        print("PyQt6 required for GUI. Install: pip install PyQt6")
        sys.exit(1)
    
    set_app_user_model_id()
    
    # Suppress Qt font warnings
    os.environ['QT_LOGGING_RULES'] = 'qt.text.font.db=false'
    
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)
    
    # Broadcast icon immediately to Taskbar before loading engines
    icon = create_app_icon(64, dark_mode=True)
    if icon:
        app.setWindowIcon(icon)
    
    win = MainWindow()
    if not win.windowIcon().isNull():
        app.setWindowIcon(win.windowIcon())
    else:
         pass
         
    win.showMaximized()
    win.activateWindow()
    win.raise_()
    sys.exit(app.exec())


def cli_main():
    import argparse
    import sys
    

    if len(sys.argv) == 1:
        launch_gui()
        return

    parser = argparse.ArgumentParser(description='OSINT Profiler v1.0')
    parser.add_argument('--email', '-e', help='Email address')
    parser.add_argument('--phone', '-p', help='Phone number')
    parser.add_argument('--country-code', '-c', help='Country code for phone (e.g., 91 for India, 1 for USA)')
    parser.add_argument('--username', '-u', help='Username')
    parser.add_argument('--gui', '-g', action='store_true', help='Launch GUI')
    parser.add_argument('--max-search', '-m', type=int, default=30, help='Max search results')
    parser.add_argument('--format', '-f', choices=['json','txt','html','pdf','all'], default='json', help='Output format')
    parser.add_argument('--output', '-o', default='reports', help='Output directory')
    parser.add_argument('--timezone', '-t', default='UTC', help='Timezone')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    parser.add_argument('--proxy', help='Rotating proxy URL (e.g. http://user:pass@host:port)')
    parser.add_argument('--truecaller-id', help='Truecaller temporary installation ID for API access')
    parser.add_argument('--deep', '-d', action='store_true', help='Remove query limits for thorough (but slower) investigations')
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    

    if not PHONENUMBERS_AVAILABLE and args.phone:
        print("\n⚠️  WARNING: phonenumbers library not installed!")
        print("Install it for full phone intelligence features:")
        print("    pip install phonenumbers\n")
    
    if args.gui:
        launch_gui()
        return
    
    if not (args.email or args.phone or args.username):
        parser.error("Provide --email or --phone or --username or use --gui")
    
    report_config = DEFAULT_REPORT_CONFIG.copy()
    report_config['timezone'] = args.timezone
    
    engine = OSINTEngine(proxy=args.proxy, truecaller_id=args.truecaller_id, deep_scan=args.deep)
    
    def cb(p,m):
        print(f"\rProgress: {p}% - {m}", end='', flush=True)
    
    report = engine.investigate(
        email=args.email, 
        phone=args.phone,
        country_code=args.country_code,
        username=args.username, 
        max_search=args.max_search, 
        progress_callback=cb
    )
    
    print("\nDone.")
    os.makedirs(args.output, exist_ok=True)
    base = build_report_basename(
        email=args.email,
        phone=args.phone,
        username=args.username
    )
    
    formats = ['json','txt','html','pdf'] if args.format == 'all' else [args.format]
    
    for fmt in formats:
        fname = f"{base}.{fmt}"
        if fmt == 'json':
            path = engine.report_generator.generate_json(report, fname, report_config)
        elif fmt == 'txt':
            path = engine.report_generator.generate_txt(report, fname, report_config)
        elif fmt == 'html':
            path = engine.report_generator.generate_html(report, fname, report_config)
        elif fmt == 'pdf':
            path = engine.report_generator.generate_pdf(report, fname, report_config)
        
        if path:
            print(f"Generated {fmt.upper()}: {path}")
    
    print("\nSummary:")
    params = report.get('parameters', {})
    if params.get('email'):
        print(f"Email: {params['email']}")
    if params.get('phone'):
        print(f"Phone: {params['phone']}")
        if params.get('country_code'):
            print(f"Country Code: +{params['country_code']}")
    if params.get('username'):
        print(f"Username: {params['username']}")
    
    stats = report.get('statistics', {})
    print(f"Total findings: {stats.get('total_findings',0)}")
    print(f"Queries executed: {stats.get('queries_executed',0)}")
    print(f"Average confidence: {stats.get('average_confidence',0)}%")
    print(f"High confidence findings: {stats.get('high_confidence_findings',0)}")

def hide_console():
    if sys.platform == 'win32':
        try:
            kernel32 = ctypes.WinDLL('kernel32')
            user32 = ctypes.WinDLL('user32')
            hWnd = kernel32.GetConsoleWindow()
            if hWnd:
                user32.ShowWindow(hWnd, 0)
        except Exception:
            pass

if __name__ == '__main__':
    if len(sys.argv) == 1:
        hide_console()
    try:
        cli_main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)