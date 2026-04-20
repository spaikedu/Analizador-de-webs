    </main>
    <footer class="footer">
        <span>WP Security Analyzer v<?= APP_VERSION ?></span>
        <span class="footer-dot">◆</span>
        <span>Hecho por <a href="https://eduardomartinezmarin.es" target="_blank" rel="noopener" style="color:inherit;text-decoration:underline">Edu Martínez</a></span>
        <span class="footer-dot">◆</span>
        <span>Uso autorizado únicamente</span>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="/wp-analyzer/assets/js/app.js?v=<?= APP_VERSION ?>"></script>
    <?php if (!empty($pageScript)): ?>
    <script><?= $pageScript ?></script>
    <?php endif; ?>
</body>
</html>
