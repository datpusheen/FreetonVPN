/**
 * Freeton VPN - Homepage Interactive Script
 * Author: pishun
 */

document.addEventListener('DOMContentLoaded', () => {
  initNavbar();
  initMockupInteractive();
  initCopyButtons();
  initBackToTop();
  initSmoothScroll();
});

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

  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      isConnected = !isConnected;
      if (isConnected) {
        toggleBtn.classList.remove('off');
        statusBadge.innerHTML = '<span class="status-dot"></span> ĐÃ KẾT NỐI (BẢO VỆ)';
        statusBadge.style.color = '#34d399';
        showToast('⚡ Freeton VPN: Đã kích hoạt kết nối WireGuard an toàn!');
      } else {
        toggleBtn.classList.add('off');
        statusBadge.innerHTML = '<span class="status-dot" style="background:#64748b; box-shadow:none;"></span> CHƯA KẾT NỐI';
        statusBadge.style.color = '#94a3b8';
        showToast('Freeton VPN: Đã ngắt kết nối đường hầm WireGuard.');
      }
    });
  }

  // Allow clicking mock server rows
  serverRows.forEach(row => {
    row.addEventListener('click', () => {
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
        showToast(`Đã chuyển sang máy chủ ${name} (${country}) - ${ping}`);
      }
    });
  });
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
        showToast(`✔ Đã sao chép ${label}: "${textToCopy}" vào bộ nhớ tạm!`);
        
        // Button visual feedback
        const originalText = btn.innerHTML;
        btn.innerHTML = '✔ Đã sao chép';
        btn.style.borderColor = '#10b981';
        btn.style.color = '#34d399';

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
  toast.innerHTML = `<span>⚡</span> <span>${message}</span>`;
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
