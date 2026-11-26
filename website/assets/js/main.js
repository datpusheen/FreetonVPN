/**
 * Freeton VPN - Homepage Interactive Script
 * Author: pishun
 */

document.addEventListener('DOMContentLoaded', () => {
  initSiteMetadata();
  initNavbar();
  initMockupInteractive();
  initCopyButtons();
  initBackToTop();
  initSmoothScroll();
  initScrollProgress();
  initScrollReveal();
  initCardSpotlight();
});

/* ==========================================================================
   Shared release metadata
   ========================================================================== */
function parseVersionTuple(version) {
  const parts = String(version || '').match(/\d+/g);
  return parts ? parts.map(Number) : [0];
}

function compareVersions(a, b) {
  const va = parseVersionTuple(a);
  const vb = parseVersionTuple(b);
  const len = Math.max(va.length, vb.length);
  for (let i = 0; i < len; i += 1) {
    const da = va[i] || 0;
    const db = vb[i] || 0;
    if (da > db) return 1;
    if (da < db) return -1;
  }
  return 0;
}

function formatShortSha(sha) {
  const clean = String(sha || '').trim();
  if (clean.length <= 16) return clean;
  return `${clean.slice(0, 8)}…${clean.slice(-7)}`;
}

function formatBytesDisplay(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return '';
  const mb = (n / (1024 * 1024)).toFixed(2);
  return `${mb} MB (${n.toLocaleString('en-US')} bytes)`;
}

async function initSiteMetadata() {
  const fallback = {
    ui_version: '3.0.0',
    ui_build_date: '2026-11-26',
    published_version: '3.0.0',
    release_status: 'published',
    installer_filename: 'FreetonVPN-Setup-x64.exe',
    installer_size_bytes: 8453440,
    installer_sha256: 'b1105c4555fa6e2382d0932d12528ac664df44014b6f5ce7c3aaba50f35ac3a4',
    download_url: 'https://github.com/datpusheen/FreetonVPN/releases/download/v3.0.0/FreetonVPN-Setup-x64.exe',
    version_manifest_url: 'https://raw.githubusercontent.com/datpusheen/FreetonVPN/refs/heads/main/version-rust.json',
    local_build_url: 'https://github.com/datpusheen/FreetonVPN/releases'
  };

  let metadata = fallback;
  try {
    const response = await fetch('assets/site.json', { cache: 'no-store' });
    if (response.ok) metadata = { ...fallback, ...(await response.json()) };
  } catch (_) {
    // Opening index.html directly has no fetch origin; static fallback remains usable.
  }

  // Prefer version-rust.json if newer or matching, so Rust v3.0.0+ metadata stays authoritative.
  if (metadata.version_manifest_url) {
    try {
      const response = await fetch(metadata.version_manifest_url, { cache: 'no-store' });
      if (response.ok) {
        const manifest = await response.json();
        const version = String(manifest.version || '').replace(/^v/i, '');
        if (version && compareVersions(version, metadata.published_version) >= 0) {
          const url = manifest.download_url || metadata.download_url;
          const filename = url ? url.split('/').pop() : metadata.installer_filename;
          metadata = {
            ...metadata,
            ui_version: version,
            published_version: version,
            ui_build_date: manifest.release_date || metadata.ui_build_date,
            installer_filename: filename || metadata.installer_filename,
            installer_size_bytes: manifest.file_size_bytes || metadata.installer_size_bytes,
            installer_sha256: manifest.sha256 || metadata.installer_sha256,
            download_url: url,
            release_changelog: Array.isArray(manifest.changelog) ? manifest.changelog : null
          };
        }
      }
    } catch (_) {
      // Static site.json remains usable if raw.githubusercontent.com is unreachable.
    }
  }

  // Keep in sync with GitHub Releases only when the latest GitHub release is >= current version.
  try {
    const response = await fetch(
      'https://api.github.com/repos/datpusheen/FreetonVPN/releases/latest',
      { headers: { Accept: 'application/vnd.github+json' }, cache: 'no-store' }
    );
    if (response.ok) {
      const release = await response.json();
      const version = String(release.tag_name || '').replace(/^v/i, '');
      const assets = release.assets || [];
      const installerAsset =
        assets.find(asset => asset.name === 'FreetonVPN-Setup-x64.exe') ||
        assets.find(asset => asset.name && asset.name.endsWith('.exe')) ||
        assets.find(asset => asset.name === 'FreetonVPN.exe');

      if (version && compareVersions(version, metadata.published_version) >= 0) {
        metadata = {
          ...metadata,
          ui_version: version,
          published_version: version,
          ui_build_date: release.published_at ? release.published_at.slice(0, 10) : metadata.ui_build_date,
          release_status: 'published',
          installer_filename: installerAsset?.name || metadata.installer_filename,
          installer_size_bytes: installerAsset?.size || metadata.installer_size_bytes,
          download_url: installerAsset?.browser_download_url || metadata.download_url,
          release_url: release.html_url,
          release_body: release.body || ''
        };
      }
    }
  } catch (_) {
    // Continue with the static/manifest metadata if the Releases API cannot be reached.
  }

  document.querySelectorAll('[data-site-version]').forEach(el => {
    el.textContent = metadata.ui_version;
  });
  document.querySelectorAll('[data-site-build-date]').forEach(el => {
    if (el.tagName === 'STRONG' || el.closest('.spec-row')) {
      el.textContent = metadata.ui_build_date;
    } else {
      const date = new Date(`${metadata.ui_build_date}T00:00:00`);
      el.textContent = Number.isNaN(date.getTime()) ? metadata.ui_build_date : date.toLocaleDateString('vi-VN');
    }
  });

  const filenameEl = document.querySelector('[data-site-filename]');
  if (filenameEl && metadata.installer_filename) {
    filenameEl.textContent = metadata.installer_filename;
  }

  const sizeEl = document.querySelector('[data-site-size]');
  const formattedSize = formatBytesDisplay(metadata.installer_size_bytes);
  if (sizeEl && formattedSize) {
    sizeEl.textContent = formattedSize;
  }

  const shaEl = document.querySelector('[data-site-sha256]');
  if (shaEl && metadata.installer_sha256) {
    shaEl.textContent = formatShortSha(metadata.installer_sha256);
    shaEl.title = metadata.installer_sha256;
    const copyBtn = shaEl.parentElement?.querySelector('.btn-copy');
    if (copyBtn) {
      copyBtn.setAttribute('data-copy', metadata.installer_sha256);
    }
  }

  const status = document.querySelector('[data-site-status] span');
  if (status) {
    status.textContent = metadata.release_status === 'local-build'
      ? `Bản Windows hiện tại · v${metadata.ui_version} · đang hoàn thiện phát hành`
      : `Bản ${metadata.published_version} · Rust Windows x64`;
  }

  document.querySelectorAll('[data-download-link]').forEach(link => {
    link.href = metadata.download_url;
    const label = link.querySelector('span');
    if (label && metadata.installer_filename) {
      label.textContent = `Tải ${metadata.installer_filename}`;
    }
  });

  const releasePage = document.querySelector('[data-release-page]');
  if (releasePage && metadata.release_url) releasePage.href = metadata.release_url;
  if (metadata.release_body) {
    renderLatestReleaseNotes(metadata.release_body);
  } else if (metadata.release_changelog) {
    renderLatestReleaseNotes(metadata.release_changelog);
  }
}

function renderLatestReleaseNotes(input) {
  const list = document.querySelector('[data-release-notes]');
  if (!list || !input) return;

  const rawLines = Array.isArray(input) ? input : String(input).split(/\r?\n/);
  const items = rawLines
    .map(line => String(line).trim())
    .filter(line => Array.isArray(input) || /^[-*•]\s+/.test(line))
    .map(line => line.replace(/^[-*•]\s+/, '')
      .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
      .replace(/\*\*(.*?)\*\*/g, '$1')
      .replace(/`([^`]+)`/g, '$1')
      .trim())
    .filter(Boolean)
    .slice(0, 8);
  if (!items.length) return;

  list.replaceChildren(...items.map(text => {
    const item = document.createElement('li');
    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.setAttribute('width', '16');
    icon.setAttribute('height', '16');
    icon.setAttribute('viewBox', '0 0 24 24');
    icon.setAttribute('fill', 'none');
    icon.setAttribute('stroke', 'currentColor');
    icon.setAttribute('stroke-width', '2.5');
    icon.setAttribute('aria-hidden', 'true');
    const check = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    check.setAttribute('points', '20 6 9 17 4 12');
    icon.appendChild(check);
    const label = document.createElement('span');
    label.textContent = text;
    item.append(icon, label);
    return item;
  }));
}

/* ==========================================================================
   Navbar & Mobile Menu
   ========================================================================== */
function initNavbar() {
  const header = document.querySelector('.site-header');
  const mobileToggle = document.querySelector('.mobile-toggle');
  const mobileDrawer = document.getElementById('mobileDrawer');

  if (header) {
    window.addEventListener('scroll', () => {
      header.classList.toggle('scrolled', window.scrollY > 20);
    }, { passive: true });
  }

  if (mobileToggle && mobileDrawer) {
    const setDrawerOpen = (open, restoreFocus = false) => {
      mobileDrawer.classList.toggle('open', open);
      mobileDrawer.hidden = !open;
      mobileDrawer.inert = !open;
      mobileToggle.setAttribute('aria-expanded', String(open));
      mobileToggle.setAttribute('aria-label', open ? 'Đóng menu điều hướng' : 'Mở menu điều hướng');
      const icon = mobileToggle.querySelector('span');
      if (icon) icon.textContent = open ? '✕' : '☰';
      if (!open && restoreFocus) mobileToggle.focus();
    };

    mobileToggle.addEventListener('click', () => {
      const isOpen = mobileDrawer.classList.contains('open');
      setDrawerOpen(!isOpen);
    });

    mobileDrawer.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', () => setDrawerOpen(false));
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && mobileDrawer.classList.contains('open')) {
        setDrawerOpen(false, true);
      }
    });
  }
}

/* ==========================================================================
   Interactive Hero App Mockup UI
   ========================================================================== */
function applyMetricClass(el, value, greenMax, warnMax) {
  if (!el) return;
  el.classList.remove('metric-good', 'metric-warn', 'metric-high');
  if (!Number.isFinite(value)) return;
  if (value < greenMax) {
    el.classList.add('metric-good');
  } else if (value < warnMax) {
    el.classList.add('metric-warn');
  } else {
    el.classList.add('metric-high');
  }
}

function initMockupInteractive() {
  const toggleBtn = document.getElementById('mockupToggle');
  const statusBadge = document.getElementById('mockupStatus');
  const serverName = document.getElementById('mockupServerName');
  const serverCountry = document.getElementById('mockupServerCountry');
  const statPing = document.getElementById('mockupPing');
  const statLoad = document.getElementById('mockupLoad');
  const serverFlag = document.getElementById('mockupFlag');
  const serverRows = document.querySelectorAll('.mockup-server-row');

  let isConnected = true;
  let transitionTimer = null;

  const setStatusContent = (dotClass, labelText, color) => {
    if (!statusBadge) return;
    const dot = document.createElement('span');
    dot.className = dotClass ? `status-dot ${dotClass}` : 'status-dot';
    dot.setAttribute('aria-hidden', 'true');
    statusBadge.replaceChildren(dot, document.createTextNode(` ${labelText}`));
    statusBadge.style.color = color;
  };

  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      if (transitionTimer) clearTimeout(transitionTimer);
      isConnected = !isConnected;
      toggleBtn.setAttribute('aria-checked', String(isConnected));

      if (isConnected) {
        toggleBtn.classList.remove('off');
        setStatusContent('connecting', 'ĐANG KẾT NỐI...', '#eab308');

        transitionTimer = setTimeout(() => {
          setStatusContent('', 'ĐÃ KẾT NỐI', '#8bd5c5');
          showToast('Đã kết nối WireGuardNT thành công.');
        }, 320);
      } else {
        toggleBtn.classList.add('off');
        setStatusContent('disconnected', 'CHƯA KẾT NỐI', '#94a3b8');
        showToast('Đã ngắt kết nối WireGuard.');
      }
    });
  }

  serverRows.forEach(row => {
    row.addEventListener('click', () => {
      serverRows.forEach(r => {
        r.classList.remove('active-selection');
        r.setAttribute('aria-pressed', 'false');
      });
      row.classList.add('active-selection');
      row.setAttribute('aria-pressed', 'true');

      const name = row.getAttribute('data-name') || '';
      const country = row.getAttribute('data-country') || '';
      const flag = row.getAttribute('data-flag') || '';
      const ping = row.getAttribute('data-ping') || '';
      const load = row.getAttribute('data-load') || '';

      if (serverName) serverName.textContent = name;
      if (serverCountry) serverCountry.textContent = country;
      if (serverFlag) serverFlag.textContent = flag;
      if (statPing) {
        statPing.textContent = ping;
        const pingNum = parseFloat(ping);
        applyMetricClass(statPing, pingNum, 80, 180);
      }
      if (statLoad) {
        statLoad.textContent = `${load} Tải`;
        const loadNum = parseFloat(load);
        applyMetricClass(statLoad, loadNum, 50, 80);
      }

      if (!isConnected && toggleBtn) {
        toggleBtn.click();
      } else {
        showToast(`Đã chọn ${name} · ${ping}`);
      }
    });
  });

  const winClose = document.querySelector('.mockup-win-btn.mockup-win-close');
  if (winClose) {
    winClose.addEventListener('click', () => {
      showToast('Cửa sổ thu nhỏ xuống khay hệ thống (System Tray).');
    });
  }

  // Micro live-ping fluctuation simulation
  setInterval(() => {
    if (!isConnected || !statPing) return;
    const match = statPing.textContent.match(/^(\d+)\s*ms$/);
    if (match) {
      const currentVal = parseInt(match[1], 10);
      const diff = (Math.random() > 0.5 ? 1 : -1) * (Math.random() < 0.35 ? 1 : 0);
      const nextVal = Math.max(18, currentVal + diff);
      statPing.textContent = `${nextVal} ms`;
      applyMetricClass(statPing, nextVal, 80, 180);
    }
  }, 3800);
}

/* ==========================================================================
   Copy to Clipboard with Toast Notification
   ========================================================================== */
function initCopyButtons() {
  const copyBtns = document.querySelectorAll('.btn-copy');

  copyBtns.forEach(btn => {
    let resetTimer = null;
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const textToCopy = btn.getAttribute('data-copy');
      const label = btn.getAttribute('data-label') || 'thông tin';

      if (!textToCopy) return;

      navigator.clipboard.writeText(textToCopy).then(() => {
        showToast(`Đã sao chép ${label}.`);

        if (resetTimer) clearTimeout(resetTimer);
        if (!btn.dataset.originalLabel) {
          btn.dataset.originalLabel = btn.textContent || 'Sao chép';
        }
        btn.textContent = '✔ Đã sao chép';
        btn.classList.add('is-copied');

        resetTimer = setTimeout(() => {
          btn.textContent = btn.dataset.originalLabel || 'Sao chép';
          btn.classList.remove('is-copied');
        }, 2000);
      }).catch(() => {
        showToast('Không thể sao chép tự động, vui lòng thử lại.');
      });
    });
  });
}

/* ==========================================================================
   Toast Notification System
   ========================================================================== */
function showToast(message) {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    container.setAttribute('role', 'status');
    container.setAttribute('aria-live', 'polite');
    container.setAttribute('aria-atomic', 'true');
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast';
  const icon = document.createElement('span');
  icon.className = 'toast-mark';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = '·';
  const content = document.createElement('span');
  content.textContent = message;
  toast.append(icon, content);
  container.appendChild(toast);

  setTimeout(() => {
    if (toast.parentNode) {
      toast.parentNode.removeChild(toast);
    }
  }, 3000);
}

/* ==========================================================================
   Back To Top & Smooth Navigation
   ========================================================================== */
function initBackToTop() {
  const backToTopBtn = document.querySelector('.back-to-top');
  if (backToTopBtn) {
    backToTopBtn.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }
}

function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      const targetId = this.getAttribute('href');
      if (targetId === '#' || targetId === '') return;
      const targetElement = document.querySelector(targetId);
      if (targetElement) {
        e.preventDefault();
        const headerOffset = 80;
        const elementPosition = targetElement.getBoundingClientRect().top;
        const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

        window.scrollTo({
          top: offsetPosition,
          behavior: 'smooth'
        });
      }
    });
  });
}

/* ==========================================================================
   Scroll Progress Indicator
   ========================================================================== */
function initScrollProgress() {
  const progressBar = document.getElementById('scrollProgressBar');
  if (!progressBar) return;

  let ticking = false;
  const updateProgress = () => {
    const scrollTop = window.scrollY || document.documentElement.scrollTop;
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    const scrollPercent = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
    progressBar.style.width = `${Math.min(100, Math.max(0, scrollPercent))}%`;
    ticking = false;
  };

  window.addEventListener('scroll', () => {
    if (!ticking) {
      window.requestAnimationFrame(updateProgress);
      ticking = true;
    }
  }, { passive: true });

  updateProgress();
}

/* ==========================================================================
   Intersection Observer Scroll Reveal System
   ========================================================================== */
function initScrollReveal() {
  const revealElements = document.querySelectorAll('.reveal');
  if (!revealElements.length) return;

  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReducedMotion || !('IntersectionObserver' in window)) {
    revealElements.forEach(el => el.classList.add('is-revealed'));
    return;
  }

  document.querySelectorAll('.stagger-group').forEach(group => {
    const items = group.querySelectorAll('.reveal');
    items.forEach((item, index) => {
      const delay = Math.min(index * 90, 600);
      item.style.setProperty('--stagger-delay', `${delay}ms`);
    });
  });

  const observerOptions = {
    root: null,
    rootMargin: '0px 0px -40px 0px',
    threshold: 0.08
  };

  const observer = new IntersectionObserver((entries, obs) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-revealed');
        obs.unobserve(entry.target);
      }
    });
  }, observerOptions);

  revealElements.forEach(el => observer.observe(el));
}

/* ==========================================================================
   Interactive Card Mouse Spotlight
   ========================================================================== */
function initCardSpotlight() {
  if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return;

  const cards = document.querySelectorAll(
    '.feature-card, .step-card, .release-card, .credit-card, .download-main-card'
  );

  cards.forEach(card => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      card.style.setProperty('--mouse-x', `${x}px`);
      card.style.setProperty('--mouse-y', `${y}px`);
    }, { passive: true });
  });
}
