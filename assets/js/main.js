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
async function initSiteMetadata() {
  const fallback = {
    ui_version: '2.4.2',
    ui_build_date: '2026-09-10',
    published_version: '2.4.1',
    release_status: 'local-build',
    download_url: 'https://github.com/datpusheen/FreetonVPN/releases/latest/download/FreetonVPN.exe',
    local_build_url: '../dist/FreetonVPN.exe'
  };

  let metadata = fallback;
  try {
    const response = await fetch('assets/site.json', { cache: 'no-store' });
    if (response.ok) metadata = { ...fallback, ...(await response.json()) };
  } catch (_) {
    // Opening index.html directly has no fetch origin; static fallback remains usable.
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

  const status = document.querySelector('[data-site-status] span');
  if (status) {
    status.textContent = metadata.release_status === 'local-build'
      ? `Bản Windows hiện tại · UI ${metadata.ui_version} · đang hoàn thiện phát hành`
      : `Bản ${metadata.published_version} · Windows desktop`;
  }
  document.querySelectorAll('[data-download-link]').forEach(link => {
    link.href = metadata.download_url;
  });
}

/* ==========================================================================
   Navbar & Mobile Menu
   ========================================================================== */
function initNavbar() {
  const header = document.querySelector('.site-header');
  const mobileToggle = document.querySelector('.mobile-toggle');
  const mobileDrawer = document.querySelector('.mobile-drawer');

  // Sticky header blur effect on scroll
  window.addEventListener('scroll', () => {
    if (window.scrollY > 20) {
      header.classList.add('scrolled');
    } else {
      header.classList.remove('scrolled');
    }
  });

  // Mobile menu toggle
  if (mobileToggle && mobileDrawer) {
    mobileToggle.addEventListener('click', () => {
      mobileDrawer.classList.toggle('open');
      const icon = mobileToggle.querySelector('span');
      if (icon) {
        icon.textContent = mobileDrawer.classList.contains('open') ? '✕' : '☰';
      }
    });

    // Close mobile menu on link click
    mobileDrawer.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', () => {
        mobileDrawer.classList.remove('open');
        const icon = mobileToggle.querySelector('span');
        if (icon) icon.textContent = '☰';
      });
    });
  }
}

/* ==========================================================================
   Interactive Hero App Mockup UI
   ========================================================================== */
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

  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      if (transitionTimer) clearTimeout(transitionTimer);
      isConnected = !isConnected;

      if (isConnected) {
        toggleBtn.classList.remove('off');
        // Show realistic quick connecting state
        statusBadge.innerHTML = '<span class="status-dot connecting"></span> ĐANG KẾT NỐI...';
        statusBadge.style.color = '#eab308';
        
        transitionTimer = setTimeout(() => {
          statusBadge.innerHTML = '<span class="status-dot"></span> ĐÃ KẾT NỐI';
          statusBadge.style.color = '#8bd5c5';
          showToast('Đã kết nối WireGuard thành công.');
        }, 320);
      } else {
        toggleBtn.classList.add('off');
        statusBadge.innerHTML = '<span class="status-dot disconnected"></span> CHƯA KẾT NỐI';
        statusBadge.style.color = '#94a3b8';
        showToast('Đã ngắt kết nối WireGuard.');
      }
    });
  }

  // Allow clicking mock server rows
  serverRows.forEach(row => {
    row.addEventListener('click', () => {
      serverRows.forEach(r => r.classList.remove('active-selection'));
      row.classList.add('active-selection');

      const name = row.getAttribute('data-name');
      const country = row.getAttribute('data-country');
      const flag = row.getAttribute('data-flag');
      const ping = row.getAttribute('data-ping');
      const load = row.getAttribute('data-load');

      if (serverName) serverName.textContent = name;
      if (serverCountry) serverCountry.textContent = country;
      if (serverFlag) serverFlag.textContent = flag;
      if (statPing) statPing.textContent = ping;
      if (statLoad) statLoad.textContent = load;

      if (!isConnected && toggleBtn) {
        toggleBtn.click();
      } else {
        showToast(`Đã chọn ${name} · ${ping}`);
      }
    });
  });

  // Windows caption controls feedback
  const winClose = document.querySelector('.mockup-win-btn.mockup-win-close');
  if (winClose) {
    winClose.addEventListener('click', () => {
      showToast('Cửa sổ sẽ thu nhỏ xuống khay hệ thống (System Tray).');
    });
  }

  // Micro live-ping fluctuation simulation to give a real-time responsive feel
  setInterval(() => {
    if (!isConnected || !statPing) return;
    const match = statPing.textContent.match(/^(\d+)\s*ms$/);
    if (match) {
      const currentVal = parseInt(match[1], 10);
      const diff = (Math.random() > 0.5 ? 1 : -1) * (Math.random() < 0.35 ? 1 : 0);
      const nextVal = Math.max(18, currentVal + diff);
      statPing.textContent = `${nextVal} ms`;
    }
  }, 3800);
}

/* ==========================================================================
   Copy to Clipboard with Toast Notification
   ========================================================================== */
function initCopyButtons() {
  const copyBtns = document.querySelectorAll('.btn-copy');

  copyBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const textToCopy = btn.getAttribute('data-copy');
      const label = btn.getAttribute('data-label') || 'thông tin';

      if (!textToCopy) return;

      navigator.clipboard.writeText(textToCopy).then(() => {
        showToast(`Đã sao chép ${label}.`);
        
        // Button visual feedback
        const originalText = btn.innerHTML;
        btn.innerHTML = '✔ Đã sao chép';
        btn.style.borderColor = '#8bd5c5';
        btn.style.color = '#8bd5c5';

        setTimeout(() => {
          btn.innerHTML = originalText;
          btn.style.borderColor = '';
          btn.style.color = '';
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
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast';
  const icon = document.createElement('span');
  icon.className = 'toast-mark';
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

  // If user prefers reduced motion or no IntersectionObserver support, reveal instantly
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReducedMotion || !('IntersectionObserver' in window)) {
    revealElements.forEach(el => el.classList.add('is-revealed'));
    return;
  }

  // Auto-calculate stagger delays for child elements in .stagger-group
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
